package database

import (
	"database/sql/driver"
	"encoding/json"
	"fmt"
)

// NullRawMessage represents a nullable jsonb column.
// json.RawMessage cannot be used directly as a query argument or Scan target
// for nullable columns: a nil []byte is not translated to SQL NULL by the
// driver (unlike Scan, where NULL correctly maps to a nil []byte).
type NullRawMessage struct {
	RawMessage json.RawMessage
	Valid      bool
}

// Scan implements the Scanner interface.
func (n *NullRawMessage) Scan(value interface{}) error {
	if value == nil {
		n.RawMessage, n.Valid = nil, false
		return nil
	}

	n.Valid = true
	switch v := value.(type) {
	case []byte:
		n.RawMessage = append(json.RawMessage(nil), v...)
	case string:
		n.RawMessage = json.RawMessage(v)
	default:
		return fmt.Errorf("unsupported Scan type for NullRawMessage: %T", value)
	}

	return nil
}

// Value implements the driver Valuer interface.
func (n NullRawMessage) Value() (driver.Value, error) {
	if !n.Valid || len(n.RawMessage) == 0 {
		return nil, nil
	}

	return []byte(n.RawMessage), nil
}
