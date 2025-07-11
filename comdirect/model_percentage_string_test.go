package comdirect

import (
	"encoding/json"
	"testing"
)

func TestUnmarshalPercentageString(t *testing.T) {
	tests := []struct {
		input   string
		wantErr bool
	}{
		// Valid inputs
		{input: "0", wantErr: false},
		{input: "100.0", wantErr: false},
		{input: "-100.0", wantErr: false},
		{input: "100.", wantErr: false},
		{input: "", wantErr: false},
		{input: "1.123123123123213123123123123123", wantErr: false},
		// Invalid inputs
		{input: "x0", wantErr: true},
		{input: "0 joe", wantErr: true},
	}
	for _, tc := range tests {
		var p PercentageString
		err := json.Unmarshal([]byte(`"`+tc.input+`"`), &p)
		if err != nil {
			if !tc.wantErr {
				t.Fatalf("Cannot unmarshal PercentageString: %v", err)
			}
			continue
		}
		if tc.wantErr {
			t.Fatalf("Wanted error, got successful unmarshal for input %q", tc.input)
		}
		got := p.GetPercentString()
		if got != tc.input {
			t.Errorf("Wrong PercentageString: want %v, got %v", tc.input, got)
		}
	}
}

func TestMarshalPercentageString(t *testing.T) {
	tests := []struct {
		s string
	}{
		{s: "2025-01-01"},
	}
	for _, tc := range tests {
		d := NewPercentageString()
		d.SetPercentString(tc.s)
		bs, err := json.Marshal(d)
		if err != nil {
			t.Fatalf("Cannot marshal DateTimeString: %v", err)
		}
		got := string(bs)
		want := `"` + tc.s + `"`
		if got != want {
			t.Errorf("Wrong marshalled DateTime: want %q, got %q", want, got)
		}
	}
}
