package comdirect

import (
	"encoding/json"
	"testing"
	"time"
)

func TestUnmarshalDateTimeString(t *testing.T) {
	locZurich, _ := time.LoadLocation("Europe/Zurich")
	tests := []struct {
		input string
		want  time.Time
	}{
		{
			// Short offset, as used in the REST API (as of July 2025).
			input: `"2025-07-09T17:36:02+02"`,
			want:  time.Date(2025, 7, 9, 17, 36, 2, 0, locZurich),
		},
		{
			input: `"2025-07-09T17:36:02+02:00"`,
			want:  time.Date(2025, 7, 9, 17, 36, 2, 0, locZurich),
		},
		{
			input: `"2025-07-09T17:36:02Z"`,
			want:  time.Date(2025, 7, 9, 17, 36, 2, 0, time.UTC),
		},
	}
	for _, tc := range tests {
		var s DateTimeString
		err := json.Unmarshal([]byte(tc.input), &s)
		if err != nil {
			t.Fatalf("Cannot unmarshal DateTimeString: %v", err)
		}
		got := s.GetDateTime()
		if !got.Equal(tc.want) {
			t.Errorf("Wrong DateTime: want %v, got %v", tc.want, got)
		}
	}
}

func TestMarshalDateTimeString(t *testing.T) {
	locZurich, _ := time.LoadLocation("Europe/Zurich")
	tests := []struct {
		t    time.Time
		want string
	}{
		{
			// UTC (Z)
			t:    time.Date(2025, 1, 31, 4, 5, 6, 0, time.UTC),
			want: `"2025-01-31T04:05:06Z"`,
		},
		{
			// CET
			t:    time.Date(2025, 1, 31, 4, 5, 6, 0, locZurich),
			want: `"2025-01-31T04:05:06+01:00"`,
		},
		{
			// CEST
			t:    time.Date(2025, 7, 31, 4, 5, 6, 0, locZurich),
			want: `"2025-07-31T04:05:06+02:00"`,
		},
	}
	for _, tc := range tests {
		d := NewDateTimeString()
		d.SetDateTime(tc.t)
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
