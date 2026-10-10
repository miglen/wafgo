package wafgo

import (
	"net/http"
	"reflect"
	"testing"
)

func TestEngineOwnsHeaders(t *testing.T) {
	headers := http.Header{"X-Example": {"original", "second"}}
	want := headers.Clone()
	eng, err := New(Options{Headers: headers})
	if err != nil {
		t.Fatal(err)
	}

	// Exercise both the map and its nested slices; a shallow copy is insufficient.
	headers["X-Example"][0] = "changed"
	headers.Set("X-New", "caller")
	if got := eng.Headers(); !reflect.DeepEqual(got, want) {
		t.Fatalf("caller changed engine headers: got %v, want %v", got, want)
	}

	for _, snapshot := range []http.Header{eng.Headers(), eng.Options().Headers} {
		snapshot["X-Example"][1] = "changed"
		snapshot.Set("X-New", "snapshot")
	}
	if got := eng.Headers(); !reflect.DeepEqual(got, want) {
		t.Fatalf("snapshot changed engine headers: got %v, want %v", got, want)
	}
	if got := eng.Options().Headers; !reflect.DeepEqual(got, want) {
		t.Fatalf("snapshot changed engine options: got %v, want %v", got, want)
	}
}

func TestEngineHeaderDefaults(t *testing.T) {
	for _, tc := range []struct {
		name    string
		headers http.Header
		want    http.Header
	}{
		{name: "nil uses defaults", want: DefaultHeaders()},
		{name: "empty stays empty", headers: http.Header{}, want: http.Header{}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			eng, err := New(Options{Headers: tc.headers})
			if err != nil {
				t.Fatal(err)
			}
			if got := eng.Options().Headers; !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("Options().Headers = %v, want %v", got, tc.want)
			}
			if got := eng.Headers(); !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("Headers() = %v, want %v", got, tc.want)
			}
			eng.Options().Headers.Set("X-New", "snapshot")
			if got := eng.Headers(); !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("snapshot changed engine headers: got %v, want %v", got, tc.want)
			}
		})
	}
}
