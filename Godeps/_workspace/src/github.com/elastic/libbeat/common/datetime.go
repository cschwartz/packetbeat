package common

import (
	"encoding/json"
	"errors"
	"time"
)

// Layout to be used in the timestamp marshaling/unmarshaling everywhere.
// The timezone must always be UTC.
const TsLayout = "2006-01-02T15:04:05.000Z"

type Time time.Time

// MarshalJSON implements json.Marshaler interface.
// The time is a quoted string in the JsTsLayout format.
func (t Time) MarshalJSON() ([]byte, error) {
	return json.Marshal(time.Time(t).UTC().Format(TsLayout))
}

// UnmarshalJSON implements js.Unmarshaler interface.
// The time is expected to be a quoted string in TsLayout
// format.
func (t *Time) UnmarshalJSON(data []byte) (err error) {
	if data[0] != []byte(`"`)[0] || data[len(data)-1] != []byte(`"`)[0] {
		return errors.New("Not quoted")
	}
	*t, err = ParseTime(string(data[1 : len(data)-1]))
	return
}

// ParseTime parses a time in the TsLayout format.
func ParseTime(timespec string) (Time, error) {
	t, err := time.Parse(TsLayout, timespec)
	return Time(t), err
}

// MustParseTime is a convenience equivalent of the ParseTime function
// that panics in case of errors.
func MustParseTime(timespec string) Time {
	ts, err := ParseTime(timespec)
	if err != nil {
		panic(err)
	}
	return ts
}
