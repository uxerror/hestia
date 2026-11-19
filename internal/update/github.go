package update

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// updateRepo is the GitHub repository with releases; set at build time with
// -ldflags "-X github.com/uxerror/hestia/internal/update.updateRepo=owner/name".
var updateRepo = "uxerror/hestia"

// DefaultAPI is the GitHub API base URL.
const DefaultAPI = "https://api.github.com"

// Limits of the release download.
const (
	MaxBinary       = 64 << 20
	maxSmallAsset   = 1 << 20
	DownloadTimeout = 5 * time.Minute
	checkTimeout    = 30 * time.Second
)

// Asset is one downloadable file of a release.
type Asset struct {
	Name string
	URL  string
	Size int64
}

// Release is the part of a GitHub release the updater needs.
type Release struct {
	Tag      string
	NotesURL string
	Assets   map[string]Asset
}

// GitHub talks to the releases API. No token is used.
type GitHub struct {
	BaseURL string // default DefaultAPI
	Repo    string // default updateRepo
	HTTP    *http.Client
}

func (g *GitHub) client() *http.Client {
	if g.HTTP != nil {
		return g.HTTP
	}
	return http.DefaultClient
}

func (g *GitHub) get(ctx context.Context, url, accept string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", accept)
	req.Header.Set("User-Agent", "hestia-controller")
	return g.client().Do(req)
}

// Latest returns the latest published release.
func (g *GitHub) Latest(ctx context.Context) (Release, error) {
	return g.release(ctx, "releases/latest", "релизов пока нет")
}

// ReleaseByTag returns the release with the given tag (pre-releases too).
func (g *GitHub) ReleaseByTag(ctx context.Context, tag string) (Release, error) {
	return g.release(ctx, "releases/tags/"+url.PathEscape(tag), "релиза "+tag+" нет")
}

// Repository returns the repository with releases ("owner/name").
func (g *GitHub) Repository() string {
	if g.Repo != "" {
		return g.Repo
	}
	return updateRepo
}

func (g *GitHub) release(ctx context.Context, path, notFound string) (Release, error) {
	base := g.BaseURL
	if base == "" {
		base = DefaultAPI
	}
	ctx, cancel := context.WithTimeout(ctx, checkTimeout)
	defer cancel()
	resp, err := g.get(ctx, strings.TrimRight(base, "/")+"/repos/"+g.Repository()+"/"+path, "application/vnd.github+json")
	if err != nil {
		return Release{}, err
	}
	defer resp.Body.Close()
	switch {
	case resp.StatusCode == http.StatusNotFound:
		return Release{}, errors.New(notFound)
	case resp.StatusCode != http.StatusOK:
		return Release{}, fmt.Errorf("GitHub ответил %s", resp.Status)
	}
	var raw struct {
		Tag    string `json:"tag_name"`
		URL    string `json:"html_url"`
		Assets []struct {
			Name string `json:"name"`
			URL  string `json:"browser_download_url"`
			Size int64  `json:"size"`
		} `json:"assets"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 4<<20)).Decode(&raw); err != nil {
		return Release{}, fmt.Errorf("ответ GitHub не разобран: %w", err)
	}
	if raw.Tag == "" {
		return Release{}, errors.New("в ответе GitHub нет тега релиза")
	}
	rel := Release{Tag: raw.Tag, NotesURL: raw.URL, Assets: map[string]Asset{}}
	for _, a := range raw.Assets {
		rel.Assets[a.Name] = Asset{Name: a.Name, URL: a.URL, Size: a.Size}
	}
	return rel, nil
}

// Download fetches an asset, refusing anything larger than limit bytes.
func (g *GitHub) Download(ctx context.Context, a Asset, limit int64) ([]byte, error) {
	resp, err := g.get(ctx, a.URL, "application/octet-stream")
	if err != nil {
		return nil, fmt.Errorf("загрузка %s: %w", a.Name, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("загрузка %s: GitHub ответил %s", a.Name, resp.Status)
	}
	if resp.ContentLength > limit {
		return nil, fmt.Errorf("%s слишком велик (%d байт, лимит %d)", a.Name, resp.ContentLength, limit)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if err != nil {
		return nil, fmt.Errorf("загрузка %s: %w", a.Name, err)
	}
	if int64(len(b)) > limit {
		return nil, fmt.Errorf("%s слишком велик (лимит %d байт)", a.Name, limit)
	}
	return b, nil
}

// FetchVerified downloads SHA256SUMS, its signature and the server binary of
// rel, and returns the binary only if the signature and the hash are right.
func (g *GitHub) FetchVerified(ctx context.Context, rel Release, pubKey []byte) ([]byte, error) {
	need := func(n string) (Asset, error) {
		a, ok := rel.Assets[n]
		if !ok {
			return Asset{}, fmt.Errorf("в релизе %s нет файла %s", rel.Tag, n)
		}
		return a, nil
	}
	var files [3]Asset
	for i, n := range []string{SumsName, SigName, ServerAsset} {
		a, err := need(n)
		if err != nil {
			return nil, err
		}
		files[i] = a
	}
	sums, err := g.Download(ctx, files[0], maxSmallAsset)
	if err != nil {
		return nil, err
	}
	sig, err := g.Download(ctx, files[1], maxSmallAsset)
	if err != nil {
		return nil, err
	}
	parsed, err := VerifySums(pubKey, sums, sig)
	if err != nil {
		return nil, err
	}
	bin, err := g.Download(ctx, files[2], MaxBinary)
	if err != nil {
		return nil, err
	}
	if err := CheckAsset(parsed, ServerAsset, bin); err != nil {
		return nil, err
	}
	return bin, nil
}
