package comdirect

import (
	"testing"

	"github.com/google/go-cmp/cmp"
)

func TestGetRemittanceInfoList(t *testing.T) {
	tests := []struct {
		input string
		want  []string
	}{
		{
			input: "01Festgeld                           02End-to-End-Ref.:                   03nicht angegeben",
			want: []string{
				"Festgeld",
				"End-to-End-Ref.:",
				"nicht angegeben",
			},
		},
		{
			input: "Something strange",
			want: []string{
				"Something strange",
			},
		},
		{
			// Each "line" is just 34 characters long (1 less than expected).
			input: "01Festgeld                          02End-to-End-Ref.:                  03nicht angegeben",
			want: []string{
				"01Festgeld                          02End-to-End-Ref.:                  03nicht angegeben",
			},
		},
		{
			// Second line is empty
			input: "01Festgeld                           02",
			want: []string{
				"Festgeld",
				"",
			},
		},
		{
			// One line
			input: "01Festgeld                           ",
			want: []string{
				"Festgeld",
			},
		},
		{
			// It's 35 unicode (or Latin1?) characters per line, not 35 bytes.
			input: "01Fästgeld                           02Änd-to-End-Ref.:                   03nicht angegeben",
			want: []string{
				"Fästgeld",
				"Änd-to-End-Ref.:",
				"nicht angegeben",
			},
		},
	}
	for _, tc := range tests {
		a := NewAccountTransaction()
		a.SetRemittanceInfo(tc.input)
		got := a.GetRemittanceInfoList()
		if diff := cmp.Diff(tc.want, got); diff != "" {
			t.Errorf("Diff in remittance infos: (-want, +got): %s", diff)
		}
	}
}
