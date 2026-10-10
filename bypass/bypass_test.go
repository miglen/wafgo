package bypass

import "testing"

func TestForMatchesProductAndFullName(t *testing.T) {
	for _, q := range []string{"Cloudflare", "cloudflare", "Cloudflare (Cloudflare Inc.)", "CLOUDFLARE"} {
		w, ok := For(q)
		if !ok || w.Product != "Cloudflare" {
			t.Errorf("For(%q) = %q, %v", q, w.Product, ok)
		}
		if len(w.References) == 0 {
			t.Errorf("For(%q) has no references", q)
		}
	}
	if _, ok := For("No Such WAF"); ok {
		t.Error("unknown WAF should not match")
	}
}

func TestEveryReferenceHasSourceAndURL(t *testing.T) {
	for _, w := range wafBypasses {
		for _, r := range w.References {
			if r.URL == "" || r.Source == "" || r.Summary == "" {
				t.Errorf("%s: incomplete reference %+v", w.Product, r)
			}
		}
	}
}

func TestTechniquesSortedAndComplete(t *testing.T) {
	ts := Techniques()
	if len(ts) == 0 {
		t.Fatal("no techniques")
	}
	for i, tq := range ts {
		if tq.Name == "" || tq.Category == "" || tq.Description == "" {
			t.Errorf("technique %d incomplete: %+v", i, tq)
		}
		if i > 0 && ts[i-1].Category > tq.Category {
			t.Errorf("techniques not sorted by category at %d", i)
		}
	}
}

func TestProducts(t *testing.T) {
	p := Products()
	if len(p) != len(wafBypasses) {
		t.Fatalf("Products returned %d, want %d", len(p), len(wafBypasses))
	}
	for i := 1; i < len(p); i++ {
		if p[i-1] > p[i] {
			t.Error("Products not sorted")
		}
	}
}
