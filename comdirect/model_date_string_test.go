package comdirect

import (
	"encoding/json"
	"testing"
)

func TestUnmarshalDateString(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{
			input: `"2025-07-01"`,
			want:  "2025-07-01",
		},
	}
	for _, tc := range tests {
		var s DateString
		err := json.Unmarshal([]byte(tc.input), &s)
		if err != nil {
			t.Fatalf("Cannot unmarshal DateTimeString: %v", err)
		}
		got := s.GetDate()
		if got != tc.want {
			t.Errorf("Wrong DateTime: want %v, got %v", tc.want, got)
		}
	}
}

func TestMarshalDateString(t *testing.T) {
	tests := []struct {
		t    string
		want string
	}{
		{
			t:    "2025-01-01",
			want: `"2025-01-01"`,
		},
	}
	for _, tc := range tests {
		d := NewDateString()
		d.SetDate(tc.t)
		bs, err := json.Marshal(d)
		if err != nil {
			t.Fatalf("Cannot marshal DateTimeString: %v", err)
		}
		got := string(bs)
		if got != tc.want {
			t.Errorf("Wrong marshalled DateTime: want %q, got %q", tc.want, got)
		}
	}
}
