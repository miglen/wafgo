package wafgo

import (
	"bufio"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/miglen/wafgo/plugins"
)

// Record is one output row. The first five fields match wafw00f's JSON/CSV
// output; enforcement is a wafgo addition distinguishing an actively-blocking
// WAF from a WAF/CDN that is merely in path.
type Record struct {
	URL          string  `json:"url"`
	Detected     bool    `json:"detected"`
	TriggerURL   *string `json:"trigger_url"`
	Firewall     string  `json:"firewall"`
	Manufacturer string  `json:"manufacturer"`
	Enforcement  string  `json:"enforcement,omitempty"`
}

// NewRecord builds a record the way wafw00f's buildResultRecord does. waf is
// a full plugin name, "generic", or "" for no detection.
func NewRecord(url, waf, triggerURL string) Record {
	r := Record{URL: url}
	if triggerURL != "" {
		t := triggerURL
		r.TriggerURL = &t
	}
	switch waf {
	case "":
		r.Firewall, r.Manufacturer = "None", "None"
	case "generic":
		r.Detected = true
		r.Firewall, r.Manufacturer = "Generic", "Unknown"
	default:
		r.Detected = true
		r.Firewall, r.Manufacturer = plugins.SplitName(waf)
	}
	return r
}

// Records converts a report into output rows (one per detected WAF).
func (r *Report) Records() []Record {
	var out []Record
	for _, w := range r.WAFs {
		out = append(out, NewRecord(r.Target, w.Name, r.TriggerURL))
	}
	if r.GenericRan {
		switch {
		case r.Generic != nil:
			out = append(out, NewRecord(r.Target, "generic", r.Generic.TriggerURL))
		case len(r.WAFs) == 0:
			out = append(out, NewRecord(r.Target, "", ""))
		}
	}
	if len(out) == 0 && len(r.WAFs) == 0 {
		out = append(out, NewRecord(r.Target, "", ""))
	}
	// Tag detections with the enforcement verdict (CDN-in-path vs blocking).
	if len(r.WAFs) > 0 {
		for i := range out {
			if out[i].Detected {
				out[i].Enforcement = string(r.Enforcement)
			}
		}
	}
	return out
}

// Format is an output format.
type Format string

// Supported output formats.
const (
	FormatText Format = "text"
	FormatJSON Format = "json"
	FormatCSV  Format = "csv"
)

// ParseFormat validates a format name ("txt" is accepted for text).
func ParseFormat(s string) (Format, error) {
	switch strings.ToLower(s) {
	case "text", "txt":
		return FormatText, nil
	case "json":
		return FormatJSON, nil
	case "csv":
		return FormatCSV, nil
	}
	return "", fmt.Errorf("unknown format %q (want json, csv or text)", s)
}

// FormatFromPath guesses the format from a file extension (text by default).
func FormatFromPath(path string) Format {
	switch strings.ToLower(filepath.Ext(path)) {
	case ".json":
		return FormatJSON
	case ".csv":
		return FormatCSV
	}
	return FormatText
}

// WriteRecords writes records in the given format. Unsupported formats return
// an error without writing anything.
func WriteRecords(w io.Writer, f Format, recs []Record) error {
	switch f {
	case FormatJSON:
		if recs == nil {
			recs = []Record{}
		}
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		enc.SetEscapeHTML(false)
		return enc.Encode(recs)
	case FormatCSV:
		cw := csv.NewWriter(w)
		_ = cw.Write([]string{"url", "detected", "trigger_url", "firewall", "manufacturer", "enforcement"})
		for _, r := range recs {
			t := ""
			if r.TriggerURL != nil {
				t = *r.TriggerURL
			}
			_ = cw.Write([]string{r.URL, strconv.FormatBool(r.Detected), t, r.Firewall, r.Manufacturer, r.Enforcement})
		}
		cw.Flush()
		return cw.Error()
	case FormatText:
		for _, line := range TextLines(recs) {
			if _, err := fmt.Fprintln(w, line); err != nil {
				return err
			}
		}
		return nil
	default:
		return fmt.Errorf("unknown format %q (want json, csv or text)", f)
	}
}

// TextLines renders records as right-aligned columns:
// URL, "Firewall (Manufacturer)" and the trigger URL.
func TextLines(recs []Record) []string {
	if len(recs) == 0 {
		return nil
	}
	rows := make([][3]string, len(recs))
	var width [3]int
	for i, r := range recs {
		t := "-"
		if r.TriggerURL != nil {
			t = *r.TriggerURL
		}
		rows[i] = [3]string{r.URL, fmt.Sprintf("%s (%s)", r.Firewall, r.Manufacturer), t}
		for c, v := range rows[i] {
			width[c] = max(width[c], len(v)+3)
		}
	}
	lines := make([]string, len(rows))
	for i, row := range rows {
		lines[i] = fmt.Sprintf("%*s%*s%*s", width[0], row[0], width[1], row[1], width[2], row[2])
	}
	return lines
}

// ParseHeaders reads "Name: value" lines (wafw00f's -H file format). Lines
// without a colon, blank lines and lines starting with '#' are ignored.
func ParseHeaders(r io.Reader) (http.Header, error) {
	h := http.Header{}
	sc := bufio.NewScanner(r)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		name, value, ok := strings.Cut(line, ":")
		if !ok || strings.TrimSpace(name) == "" {
			continue
		}
		h.Set(strings.TrimSpace(name), strings.TrimSpace(value))
	}
	return h, sc.Err()
}

// ReadHeadersFile parses a headers file.
func ReadHeadersFile(path string) (http.Header, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return ParseHeaders(f)
}

// ReadTargets reads targets in the format implied by name: a JSON array of
// objects with a "url" key (.json), a CSV file with a "url" column (.csv),
// or one URL per line. Blank lines and '#' comments are skipped.
// JSON input must contain exactly one document followed only by whitespace.
func ReadTargets(r io.Reader, name string) ([]string, error) {
	switch strings.ToLower(filepath.Ext(name)) {
	case ".json":
		var items []struct {
			URL string `json:"url"`
		}
		dec := json.NewDecoder(r)
		if err := dec.Decode(&items); err != nil {
			return nil, fmt.Errorf("%s: not well-formed JSON: %w", name, err)
		}
		var extra json.RawMessage
		if err := dec.Decode(&extra); err != io.EOF {
			if err != nil {
				return nil, fmt.Errorf("%s: invalid data after JSON array: %w", name, err)
			}
			return nil, fmt.Errorf("%s: expected a single JSON array", name)
		}
		var out []string
		for _, it := range items {
			if u := strings.TrimSpace(it.URL); u != "" {
				out = append(out, u)
			}
		}
		return out, nil
	case ".csv":
		rows, err := csv.NewReader(r).ReadAll()
		if err != nil {
			return nil, fmt.Errorf("%s: %w", name, err)
		}
		if len(rows) == 0 {
			return nil, nil
		}
		col := -1
		for i, h := range rows[0] {
			if strings.EqualFold(strings.TrimSpace(h), "url") {
				col = i
			}
		}
		if col < 0 {
			return nil, fmt.Errorf("%s: no \"url\" column", name)
		}
		var out []string
		for _, row := range rows[1:] {
			if col < len(row) {
				if u := strings.TrimSpace(row[col]); u != "" {
					out = append(out, u)
				}
			}
		}
		return out, nil
	default:
		var out []string
		sc := bufio.NewScanner(r)
		sc.Buffer(make([]byte, 64*1024), 1024*1024)
		for sc.Scan() {
			line := strings.TrimSpace(sc.Text())
			if line != "" && !strings.HasPrefix(line, "#") {
				out = append(out, line)
			}
		}
		return out, sc.Err()
	}
}

// NormalizeTarget adds https:// to targets given without a scheme.
func NormalizeTarget(t string) string {
	t = strings.TrimSpace(t)
	if !strings.Contains(t, "://") {
		return "https://" + t
	}
	return t
}
