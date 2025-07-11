package comdirect

import (
	"encoding/json"
	"testing"

	"github.com/google/go-cmp/cmp"
)

func TestMarshalUnmarshalCurrencyString(t *testing.T) {
	type Wrapper struct {
		Currency *CurrencyString `json:"currency"`
	}
	tests := []struct {
		currency string
	}{
		{
			currency: "EUR",
		},
	}
	for _, tc := range tests {
		c := NewCurrencyString()
		c.SetCurrency(tc.currency)
		w := Wrapper{
			Currency: c,
		}
		bs, err := json.Marshal(w)
		if err != nil {
			t.Fatalf("Cannot marshal CurrencyString: %v", err)
		}
		var w2 Wrapper
		err = json.Unmarshal(bs, &w2)
		if err != nil {
			t.Fatalf("Cannot unmarshal CurrencyString: %v", err)
		}
		if diff := cmp.Diff(w, w2); diff != "" {
			t.Errorf("Unmarshalled record differs (-want, +got): %s", diff)
		}
	}
}
