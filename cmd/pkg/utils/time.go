package utils

import "time"

func GetTimeString(t time.Time) string {
  return t.Format("02-01-2006T15:01:05")
}
