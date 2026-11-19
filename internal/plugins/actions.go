package plugins

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"time"

	"github.com/uxerror/hestia/internal/jobs"
	"github.com/uxerror/hestia/internal/store"
	"github.com/uxerror/hestia/sdk"
	"github.com/uxerror/hestia/sdk/rpc"
)

// Actions of instances (instance.action): buttons from the manifest's
// "actions". Their parameters are stored nowhere (not in the config, the
// secrets or the job log); secret ones are masked in the log during the
// call. The call runs as a short job "plugin-action" that records who ran
// which action, not its parameters.

// JobAction is the job kind of an action.
const JobAction = "plugin-action"

// ActionTimeout bounds one action.
const ActionTimeout = 60 * time.Second

// ActionDef returns the definition of an action of an instance (404 if the
// instance or the action is not there).
func (m *Manager) ActionDef(ctx context.Context, iid int64, name string) (store.PluginInstance, sdk.ActionDef, error) {
	inst, err := m.Store.GetInstance(ctx, iid)
	if errors.Is(err, store.ErrNotFound) || (err == nil && inst.Status == store.InstanceDraft) {
		return inst, sdk.ActionDef{}, newErr(http.StatusNotFound, "экземпляр не найден")
	}
	if err != nil {
		return inst, sdk.ActionDef{}, err
	}
	p, err := m.Store.GetPlugin(ctx, inst.PluginID)
	if err != nil {
		return inst, sdk.ActionDef{}, err
	}
	man, err := storedManifest(p.Manifest)
	if err != nil {
		return inst, sdk.ActionDef{}, err
	}
	for _, a := range man.Actions {
		if a.Name == name {
			return inst, a, nil
		}
	}
	return inst, sdk.ActionDef{}, newErr(http.StatusNotFound, "у экземпляра «%s» нет действия %q", inst.Name, name)
}

// actionParams checks the parameters against the action's fields.
func actionParams(def sdk.ActionDef, in map[string]any) (sdk.Config, []string, error) {
	out := sdk.Config{}
	var masks []string
	var ferrs []sdk.FieldError
	for k := range in {
		if !slices.ContainsFunc(def.Fields, func(f sdk.Field) bool { return f.Name == k }) {
			ferrs = append(ferrs, sdk.FieldError{Field: k, Msg: "нет такого поля"})
		}
	}
	for _, f := range def.Fields {
		v, ok := in[f.Name]
		if !ok || v == nil || v == "" {
			if f.Required {
				ferrs = append(ferrs, sdk.FieldError{Field: f.Name, Msg: "обязательное поле"})
			}
			continue
		}
		typ := f
		if f.Type == sdk.FieldSecret {
			typ.Type = sdk.FieldText
		}
		if msg := checkValue(typ, v); msg != "" {
			ferrs = append(ferrs, sdk.FieldError{Field: f.Name, Msg: msg})
			continue
		}
		if s, ok := v.(string); ok && f.Type == sdk.FieldSecret {
			masks = append(masks, s)
		}
		out[f.Name] = v
	}
	if len(ferrs) > 0 {
		return nil, nil, &Error{Status: http.StatusUnprocessableEntity, Msg: "Проверьте поля действия", Fields: ferrs}
	}
	return out, masks, nil
}

// RunAction runs an action of an instance and waits for it (at most
// ActionTimeout). The administrator password of "confirm": "password" is
// checked by the caller (API). The answer's download is not kept.
func (m *Manager) RunAction(ctx context.Context, iid int64, name string, in map[string]any) (sdk.ActionResult, error) {
	inst, def, err := m.ActionDef(ctx, iid, name)
	if err != nil {
		return sdk.ActionResult{}, err
	}
	if inst.PluginID == BuiltinID {
		return sdk.ActionResult{}, errBuiltinChange()
	}
	if _, _, err := m.pluginForInstances(ctx, inst.PluginID); err != nil {
		return sdk.ActionResult{}, err
	}
	m.mu.Lock()
	on, known := m.actionsOn[iid]
	m.mu.Unlock()
	if known && !slices.Contains(on, name) {
		return sdk.ActionResult{}, newErr(http.StatusConflict, "Действие «%s» сейчас недоступно", def.Label)
	}
	params, masks, err := actionParams(def, in)
	if err != nil {
		return sdk.ActionResult{}, err
	}
	m.mu.Lock()
	if m.instJobs[iid] {
		m.mu.Unlock()
		return sdk.ActionResult{}, newErr(http.StatusConflict, "с экземпляром «%s» уже выполняется задача", inst.Name)
	}
	m.instJobs[iid] = true
	m.mu.Unlock()

	type outcome struct {
		res sdk.ActionResult
		err error
	}
	done := make(chan outcome, 1)
	_, err = m.Runner.Start(JobAction, fmt.Sprintf("Hestia: действие «%s» — «%s»", def.Label, inst.Name), func(jctx context.Context, run *jobs.Run) error {
		defer m.releaseInstances(iid)
		res, err := m.callAction(jctx, run, inst, def, params, masks)
		done <- outcome{res, err}
		return err
	})
	if err != nil {
		m.releaseInstances(iid)
		return sdk.ActionResult{}, err
	}
	select {
	case o := <-done:
		return o.res, o.err
	case <-ctx.Done():
		return sdk.ActionResult{}, ctx.Err()
	}
}

func (m *Manager) callAction(ctx context.Context, run *jobs.Run, inst store.PluginInstance, def sdk.ActionDef, params sdk.Config, masks []string) (sdk.ActionResult, error) {
	s := m.conn(inst.PluginID)
	if s == nil {
		return sdk.ActionResult{}, newErr(http.StatusConflict, "плагин %s не подключён", inst.PluginID)
	}
	a := &applyJob{pluginID: inst.PluginID, instanceID: inst.ID, run: run, action: true}
	for _, v := range masks {
		a.addMask(v)
	}
	m.mu.Lock()
	m.applying[run.ID()] = a
	m.mu.Unlock()
	defer func() {
		m.mu.Lock()
		delete(m.applying, run.ID())
		m.mu.Unlock()
	}()
	run.Log("info", fmt.Sprintf("Действие «%s» экземпляра «%s» (параметры не сохраняются)", def.Label, inst.Name))
	cctx, cancel := context.WithTimeout(ctx, ActionTimeout)
	defer cancel()
	var res sdk.ActionResult
	err := s.conn.CallNoTimeout(cctx, sdk.MethodAction, sdk.ActionRequest{JobID: run.ID(), Instance: sdkInstance(inst), Action: def.Name, Params: params}, &res)
	a.stepDone(err)
	var re *rpc.Error
	switch {
	case err == nil:
	case errors.As(err, &re) && re.Code == rpc.CodeMethodNotFound:
		return res, newErr(http.StatusNotImplemented, "плагин не поддерживает действия (instance.action)")
	case errors.Is(err, context.DeadlineExceeded) || cctx.Err() != nil:
		return res, newErr(http.StatusGatewayTimeout, "действие не завершилось за %s", ActionTimeout)
	case errors.As(err, &re):
		return res, newErr(http.StatusBadGateway, "«%s»: %s", inst.Name, truncate(a.mask(re.Message), 1000))
	default:
		return res, newErr(http.StatusBadGateway, "«%s»: %s", inst.Name, a.mask(pluginErr(err).Error()))
	}
	res.Message = truncate(a.mask(res.Message), 2000)
	if d := res.Download; d != nil {
		switch {
		case len(d.Data) > sdk.MaxDownload:
			return sdk.ActionResult{}, newErr(http.StatusBadGateway, "плагин вернул файл больше 1 МБ")
		case !reDeployFile.MatchString(d.Name):
			return sdk.ActionResult{}, newErr(http.StatusBadGateway, "плагин вернул файл с недопустимым именем")
		}
		if d.MIME == "" || len(d.MIME) > 100 {
			d.MIME = "application/octet-stream"
		}
		run.Log("info", fmt.Sprintf("Файл %s (%s) отдан браузеру, Hestia его не хранит", d.Name, sizeText(int64(len(d.Data)))))
	}
	return res, nil
}

// setActionsOn records the actions an instance status enables (nil: all).
func (m *Manager) setActionsOn(iid int64, on []string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if on == nil {
		delete(m.actionsOn, iid)
		return
	}
	m.actionsOn[iid] = on
}

// ActionsEnabled returns the actions enabled now (nil: all).
func (m *Manager) ActionsEnabled(iid int64) []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	if on, ok := m.actionsOn[iid]; ok {
		return slices.Clone(on)
	}
	return nil
}
