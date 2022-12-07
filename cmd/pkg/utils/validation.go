package utils

import (
  "encoding/json"
  "fmt"
  "reflect"
)

const mandatoryTag = "mandatory"

func UnmarshalJSON(data []byte, v any) error {
  err := json.Unmarshal(data, v)
  if err != nil {
    return err
  }
  fields := reflect.ValueOf(v).Elem()
  for i := 0; i < fields.NumField(); i++ {
    tag, ok := fields.Type().Field(i).Tag.Lookup(mandatoryTag)
    if !ok {
      continue
    }
    if tag == "true" && fields.Field(i).IsZero() {
      name := fields.Type().Field(i).Name
      return fmt.Errorf("field %s is mandatory", name)
    }
  }
  return nil
}

func CheckMandatoryFields(v any) error {
  b, err := json.Marshal(v)
  if err != nil {
    return nil
  }
  cv := v
  return UnmarshalJSON(b, cv)
}
