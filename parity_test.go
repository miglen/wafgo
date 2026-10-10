package wafgo

import (
	"encoding/json"
	"net/http"
	"os"
	"slices"
	"testing"

	"github.com/miglen/wafgo/plugins"
)

// testdata/parity.json is produced by tools/parity/gen_parity.py, which runs
// the original Python wafw00f plugins against synthetic responses. Every Go
// plugin must reach exactly the same verdict.

type parityResponse struct {
	Status  int               `json:"status"`
	Reason  string            `json:"reason"`
	Headers map[string]string `json:"headers"`
	Body    string            `json:"body"`
}

type parityCase struct {
	Name     string          `json:"name"`
	Normal   *parityResponse `json:"normal"`
	Attack   *parityResponse `json:"attack"`
	Expected []string        `json:"expected"`
}

func (p *parityResponse) toResponse() *Response {
	if p == nil {
		return nil
	}
	h := http.Header{}
	for k, v := range p.Headers {
		h.Set(k, v)
	}
	return &Response{StatusCode: p.Status, Reason: p.Reason, Header: h, Body: []byte(p.Body)}
}

func TestParityWithUpstream(t *testing.T) {
	raw, err := os.ReadFile("testdata/parity.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		UpstreamPlugins int          `json:"upstream_plugins"`
		Cases           []parityCase `json:"cases"`
	}
	if err := json.Unmarshal(raw, &fixture); err != nil {
		t.Fatal(err)
	}
	if got := len(plugins.All()); got != fixture.UpstreamPlugins {
		t.Fatalf("have %d plugins, upstream fixture has %d", got, fixture.UpstreamPlugins)
	}
	if len(fixture.Cases) < 1000 {
		t.Fatalf("suspiciously few parity cases: %d", len(fixture.Cases))
	}
	for _, c := range fixture.Cases {
		site := &Site{Normal: c.Normal.toResponse(), Attack: c.Attack.toResponse()}
		var got []string
		for _, p := range plugins.All() {
			if p.Detect(site) {
				got = append(got, p.Name)
			}
		}
		slices.Sort(got)
		want := slices.Clone(c.Expected)
		slices.Sort(want)
		if !slices.Equal(got, want) {
			t.Errorf("%s:\n  go:     %q\n  python: %q", c.Name, got, want)
		}
	}
}
