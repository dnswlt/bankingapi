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

// checks if the StandardErrorResponse type satisfies the MappedNullable interface at compile time
var _ MappedNullable = &StandardErrorResponse{}

// StandardErrorResponse struct for StandardErrorResponse
type StandardErrorResponse struct {
	Code *string `json:"code,omitempty"`
	Messages []BusinessMessage `json:"messages,omitempty"`
}

// NewStandardErrorResponse instantiates a new StandardErrorResponse object
// This constructor will assign default values to properties that have it defined,
// and makes sure properties required by API are set, but the set of arguments
// will change when the set of required properties is changed
func NewStandardErrorResponse() *StandardErrorResponse {
	this := StandardErrorResponse{}
	return &this
}

// NewStandardErrorResponseWithDefaults instantiates a new StandardErrorResponse object
// This constructor will only assign default values to properties that have it defined,
// but it doesn't guarantee that properties required by API are set
func NewStandardErrorResponseWithDefaults() *StandardErrorResponse {
	this := StandardErrorResponse{}
	return &this
}

// GetCode returns the Code field value if set, zero value otherwise.
func (o *StandardErrorResponse) GetCode() string {
	if o == nil || IsNil(o.Code) {
		var ret string
		return ret
	}
	return *o.Code
}

// GetCodeOk returns a tuple with the Code field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *StandardErrorResponse) GetCodeOk() (*string, bool) {
	if o == nil || IsNil(o.Code) {
		return nil, false
	}
	return o.Code, true
}

// HasCode returns a boolean if a field has been set.
func (o *StandardErrorResponse) HasCode() bool {
	if o != nil && !IsNil(o.Code) {
		return true
	}

	return false
}

// SetCode gets a reference to the given string and assigns it to the Code field.
func (o *StandardErrorResponse) SetCode(v string) {
	o.Code = &v
}

// GetMessages returns the Messages field value if set, zero value otherwise.
func (o *StandardErrorResponse) GetMessages() []BusinessMessage {
	if o == nil || IsNil(o.Messages) {
		var ret []BusinessMessage
		return ret
	}
	return o.Messages
}

// GetMessagesOk returns a tuple with the Messages field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *StandardErrorResponse) GetMessagesOk() ([]BusinessMessage, bool) {
	if o == nil || IsNil(o.Messages) {
		return nil, false
	}
	return o.Messages, true
}

// HasMessages returns a boolean if a field has been set.
func (o *StandardErrorResponse) HasMessages() bool {
	if o != nil && !IsNil(o.Messages) {
		return true
	}

	return false
}

// SetMessages gets a reference to the given []BusinessMessage and assigns it to the Messages field.
func (o *StandardErrorResponse) SetMessages(v []BusinessMessage) {
	o.Messages = v
}

func (o StandardErrorResponse) MarshalJSON() ([]byte, error) {
	toSerialize,err := o.ToMap()
	if err != nil {
		return []byte{}, err
	}
	return json.Marshal(toSerialize)
}

func (o StandardErrorResponse) ToMap() (map[string]interface{}, error) {
	toSerialize := map[string]interface{}{}
	if !IsNil(o.Code) {
		toSerialize["code"] = o.Code
	}
	if !IsNil(o.Messages) {
		toSerialize["messages"] = o.Messages
	}
	return toSerialize, nil
}

type NullableStandardErrorResponse struct {
	value *StandardErrorResponse
	isSet bool
}

func (v NullableStandardErrorResponse) Get() *StandardErrorResponse {
	return v.value
}

func (v *NullableStandardErrorResponse) Set(val *StandardErrorResponse) {
	v.value = val
	v.isSet = true
}

func (v NullableStandardErrorResponse) IsSet() bool {
	return v.isSet
}

func (v *NullableStandardErrorResponse) Unset() {
	v.value = nil
	v.isSet = false
}

func NewNullableStandardErrorResponse(val *StandardErrorResponse) *NullableStandardErrorResponse {
	return &NullableStandardErrorResponse{value: val, isSet: true}
}

func (v NullableStandardErrorResponse) MarshalJSON() ([]byte, error) {
	return json.Marshal(v.value)
}

func (v *NullableStandardErrorResponse) UnmarshalJSON(src []byte) error {
	v.isSet = true
	return json.Unmarshal(src, &v.value)
}


