/*
comdirect REST API

Please have a look at the interfaces of comdirect REST API below. Note: Currently it is not possible to request an access token via swagger UI tools because of comdirect's proprietary authorization flow. The shown error message is due to that circumstance.

API version: 20.04
*/

// Code generated by OpenAPI Generator (https://openapi-generator.tech); DO NOT EDIT.

package comdirect

import (
	"encoding/json"
)

// checks if the Dimensions type satisfies the MappedNullable interface at compile time
var _ MappedNullable = &Dimensions{}

// Dimensions Model for dimensions.
type Dimensions struct {
	Venues []Venue `json:"venues,omitempty"`
}

// NewDimensions instantiates a new Dimensions object
// This constructor will assign default values to properties that have it defined,
// and makes sure properties required by API are set, but the set of arguments
// will change when the set of required properties is changed
func NewDimensions() *Dimensions {
	this := Dimensions{}
	return &this
}

// NewDimensionsWithDefaults instantiates a new Dimensions object
// This constructor will only assign default values to properties that have it defined,
// but it doesn't guarantee that properties required by API are set
func NewDimensionsWithDefaults() *Dimensions {
	this := Dimensions{}
	return &this
}

// GetVenues returns the Venues field value if set, zero value otherwise.
func (o *Dimensions) GetVenues() []Venue {
	if o == nil || IsNil(o.Venues) {
		var ret []Venue
		return ret
	}
	return o.Venues
}

// GetVenuesOk returns a tuple with the Venues field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *Dimensions) GetVenuesOk() ([]Venue, bool) {
	if o == nil || IsNil(o.Venues) {
		return nil, false
	}
	return o.Venues, true
}

// HasVenues returns a boolean if a field has been set.
func (o *Dimensions) HasVenues() bool {
	if o != nil && !IsNil(o.Venues) {
		return true
	}

	return false
}

// SetVenues gets a reference to the given []Venue and assigns it to the Venues field.
func (o *Dimensions) SetVenues(v []Venue) {
	o.Venues = v
}

func (o Dimensions) MarshalJSON() ([]byte, error) {
	toSerialize,err := o.ToMap()
	if err != nil {
		return []byte{}, err
	}
	return json.Marshal(toSerialize)
}

func (o Dimensions) ToMap() (map[string]interface{}, error) {
	toSerialize := map[string]interface{}{}
	if !IsNil(o.Venues) {
		toSerialize["venues"] = o.Venues
	}
	return toSerialize, nil
}

type NullableDimensions struct {
	value *Dimensions
	isSet bool
}

func (v NullableDimensions) Get() *Dimensions {
	return v.value
}

func (v *NullableDimensions) Set(val *Dimensions) {
	v.value = val
	v.isSet = true
}

func (v NullableDimensions) IsSet() bool {
	return v.isSet
}

func (v *NullableDimensions) Unset() {
	v.value = nil
	v.isSet = false
}

func NewNullableDimensions(val *Dimensions) *NullableDimensions {
	return &NullableDimensions{value: val, isSet: true}
}

func (v NullableDimensions) MarshalJSON() ([]byte, error) {
	return json.Marshal(v.value)
}

func (v *NullableDimensions) UnmarshalJSON(src []byte) error {
	v.isSet = true
	return json.Unmarshal(src, &v.value)
}


