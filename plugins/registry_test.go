package plugins

import (
	"os"
	"os/exec"
	"sync"
	"testing"
)

func TestRegistryConcurrentFirstUse(t *testing.T) {
	const helperEnv = "WAFGO_TEST_REGISTRY_FIRST_USE"
	if os.Getenv(helperEnv) != "1" {
		// A fresh process ensures earlier tests cannot warm the global caches.
		cmd := exec.Command(os.Args[0], "-test.run=^TestRegistryConcurrentFirstUse$", "-test.count=1")
		cmd.Env = append(os.Environ(), helperEnv+"=1")
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("registry helper: %v\n%s", err, out)
		}
		return
	}

	coreCount := 0
	for _, p := range registry {
		if p.Source == SourceWafw00f {
			coreCount++
		}
	}
	start := make(chan struct{})
	var wg sync.WaitGroup
	for i := range 24 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			switch i % 3 {
			case 0:
				if got := len(Core()); got != coreCount {
					t.Errorf("Core() has %d entries, want %d", got, coreCount)
				}
			case 1:
				if got := len(All()); got != len(registry) {
					t.Errorf("All() has %d entries, want %d", got, len(registry))
				}
			case 2:
				if p, ok := Lookup("Google Cloud App Armor"); !ok || p.ID != "gcparmor" {
					t.Errorf("Lookup() = %q, %v; want gcparmor, true", p.ID, ok)
				}
			}
		}()
	}
	close(start)
	wg.Wait()
}

func TestRegistryReturnsIndependentSlices(t *testing.T) {
	for _, tc := range []struct {
		name string
		list func() []Plugin
	}{
		{name: "Core", list: Core},
		{name: "All", list: All},
	} {
		t.Run(tc.name, func(t *testing.T) {
			first, second := tc.list(), tc.list()
			if len(first) == 0 || len(second) == 0 {
				t.Fatal("empty registry")
			}
			want := second[0].Name
			first[0].Name = "caller mutation"
			if second[0].Name != want {
				t.Fatal("returned slices share storage")
			}
			if got := tc.list()[0].Name; got != want {
				t.Fatalf("caller changed cached name: got %q, want %q", got, want)
			}
		})
	}
}
