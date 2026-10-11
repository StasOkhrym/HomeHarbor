package session

import (
	"bytes"
	"testing"
	"time"
)

func TestCSRFCookieRejectsShortEntropyRead(t *testing.T) {
	codec, err := NewCodec(bytes.Repeat([]byte("k"), 32), func(value []byte) (int, error) {
		value[0] = 7
		return 1, nil
	})
	if err != nil {
		t.Fatal(err)
	}

	if _, err := codec.CSRFCookie("opaque-session", time.Now().Add(time.Hour)); err == nil {
		t.Fatal("short entropy read created a CSRF cookie")
	}
}
