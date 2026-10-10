package wafgo

import (
	"bytes"
	"errors"
	"io"
	"reflect"
	"strings"
	"testing"
)

func TestReadTargetsJSONRequiresSingleDocument(t *testing.T) {
	for _, tc := range []struct {
		name  string
		input string
		want  []string
	}{
		{"empty array", "[]", nil},
		{"trailing whitespace", "[{\"url\":\" https://example.invalid \"}] \n\t", []string{"https://example.invalid"}},
		{"report fields", `[{"url":"https://example.invalid","detected":false,"firewall":"None"}]`, []string{"https://example.invalid"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ReadTargets(strings.NewReader(tc.input), "targets.json")
			if err != nil || !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("ReadTargets() = %v, %v; want %v, nil", got, err, tc.want)
			}
		})
	}

	for _, suffix := range []string{"[]", "null", `{"url":"https://second.invalid"}`, "garbage", "{"} {
		t.Run("reject "+suffix, func(t *testing.T) {
			got, err := ReadTargets(strings.NewReader(`[{"url":"https://example.invalid"}] `+suffix), "targets.json")
			if err == nil || !strings.Contains(err.Error(), "targets.json") {
				t.Fatalf("expected a named input error, got targets=%v, err=%v", got, err)
			}
			if len(got) != 0 {
				t.Fatalf("invalid input returned partial targets: %v", got)
			}
		})
	}
}

type failingInput struct{ err error }

func (r failingInput) Read([]byte) (int, error) { return 0, r.err }

func TestReadTargetsJSONPropagatesTrailingReadError(t *testing.T) {
	want := errors.New("input read failed")
	r := io.MultiReader(strings.NewReader(`[{"url":"https://example.invalid"}]`), failingInput{want})
	got, err := ReadTargets(r, "targets.json")
	if !errors.Is(err, want) || len(got) != 0 {
		t.Fatalf("ReadTargets() = %v, %v; want no targets and %v", got, err, want)
	}
}

func TestWriteRecordsRejectsUnknownFormat(t *testing.T) {
	for _, format := range []Format{"", "yaml", "jsno"} {
		t.Run(string(format), func(t *testing.T) {
			var out bytes.Buffer
			err := WriteRecords(&out, format, []Record{NewRecord("https://example.invalid", "", "")})
			if err == nil || out.Len() != 0 {
				t.Fatalf("expected error without output, got err=%v, output=%q", err, out.String())
			}
		})
	}
}

func TestRecordsRoundTripTargets(t *testing.T) {
	want := []string{"https://example.invalid/a?x=1&y=2", "https://example.invalid/b"}
	recs := []Record{NewRecord(want[0], "", ""), NewRecord(want[1], "generic", "")}
	for _, format := range []Format{FormatJSON, FormatCSV} {
		t.Run(string(format), func(t *testing.T) {
			var out bytes.Buffer
			if err := WriteRecords(&out, format, recs); err != nil {
				t.Fatal(err)
			}
			got, err := ReadTargets(&out, "report."+string(format))
			if err != nil || !reflect.DeepEqual(got, want) {
				t.Fatalf("round trip = %v, %v; want %v, nil", got, err, want)
			}
		})
	}
}
