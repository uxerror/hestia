package plugins

import (
	"bytes"
	"encoding/xml"
	"errors"
	"io"
	"strings"
)

// droppedElements are removed from icons together with their content.
var droppedElements = map[string]bool{
	"script": true, "foreignobject": true, "iframe": true, "embed": true, "object": true,
	"audio": true, "video": true, "animate": true, "set": true, "animatetransform": true, "animatemotion": true,
	"handler": true, "listener": true,
}

// SanitizeSVG re-encodes an icon without scripts, foreign content, event
// handlers (on*), external references and processing instructions. The UI
// shows icons through <img>, which does not run scripts anyway; this is the
// second line of defence (for example when the icon is opened directly).
func SanitizeSVG(b []byte) ([]byte, error) {
	dec := xml.NewDecoder(bytes.NewReader(b))
	dec.Strict = true
	var out bytes.Buffer
	var stack []string // open elements, to check nesting (RawToken does not)
	skip := 0
	root := false
	for {
		// RawToken keeps namespace prefixes as written (xlink:href).
		tok, err := dec.RawToken()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, errors.New("не разбирается как SVG")
		}
		switch t := tok.(type) {
		case xml.StartElement:
			name := qname(t.Name)
			stack = append(stack, name)
			if skip > 0 || droppedElements[strings.ToLower(t.Name.Local)] {
				skip++
				continue
			}
			if !root {
				if strings.ToLower(t.Name.Local) != "svg" || len(stack) != 1 {
					return nil, errors.New("корневой элемент не svg")
				}
				root = true
			} else if len(stack) == 1 {
				return nil, errors.New("в SVG больше одного корневого элемента")
			}
			out.WriteString("<" + name)
			for _, a := range cleanAttrs(t.Attr) {
				out.WriteString(" " + qname(a.Name) + `="`)
				_ = xml.EscapeText(&out, []byte(a.Value))
				out.WriteString(`"`)
			}
			out.WriteString(">")
		case xml.EndElement:
			name := qname(t.Name)
			if len(stack) == 0 || stack[len(stack)-1] != name {
				return nil, errors.New("не разбирается как SVG")
			}
			stack = stack[:len(stack)-1]
			if skip > 0 {
				skip--
				continue
			}
			out.WriteString("</" + name + ">")
		case xml.CharData:
			if skip == 0 && len(stack) > 0 {
				_ = xml.EscapeText(&out, t)
			}
		case xml.Comment, xml.ProcInst, xml.Directive:
			// dropped: no DOCTYPE/entities, no stylesheet instructions
		}
	}
	if !root || len(stack) != 0 {
		return nil, errors.New("пустой или незакрытый SVG")
	}
	return out.Bytes(), nil
}

func qname(n xml.Name) string {
	if n.Space != "" {
		return n.Space + ":" + n.Local
	}
	return n.Local
}

func cleanAttrs(in []xml.Attr) []xml.Attr {
	out := in[:0]
	for _, a := range in {
		name := strings.ToLower(a.Name.Local)
		val := strings.ToLower(strings.TrimSpace(a.Value))
		switch {
		case strings.HasPrefix(name, "on"):
			continue
		case name == "href" || name == "src" || name == "action" || name == "formaction":
			// Only references inside the document (#id) and inline images.
			if !strings.HasPrefix(val, "#") && !strings.HasPrefix(val, "data:image/png") && !strings.HasPrefix(val, "data:image/jpeg") {
				continue
			}
		case name == "style" && (strings.Contains(val, "url(") || strings.Contains(val, "expression") || strings.Contains(val, "@import")):
			continue
		}
		out = append(out, a)
	}
	return out
}
