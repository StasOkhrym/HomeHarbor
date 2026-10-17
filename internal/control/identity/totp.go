package identity

import (
	"crypto/hmac"
	"crypto/sha1"
	"crypto/subtle"
	"encoding/binary"
	"fmt"
	"time"
)

// matchingTOTPStep implements the fixed six-digit SHA1 profile from RFC6238.
// This calculation grants no authority: the repository must atomically consume
// the returned step against the same current seed and account auth-version.
func matchingTOTPStep(seed []byte, code string, now time.Time, lastStep int64) (int64, bool) {
	if len(seed) != 20 || len(code) != 6 || now.Unix() < 0 {
		return 0, false
	}

	for _, value := range []byte(code) {
		if value < '0' || value > '9' {
			return 0, false
		}
	}

	current := now.Unix() / 30
	var matched int64
	found := false
	// Prefer the latest matching step if the six-digit value happens to collide
	// inside the permitted window, so that value cannot admit two completions.
	for offset := int64(1); offset >= -1; offset-- {
		step := current + offset
		if step < 0 {
			continue
		}

		var counter [8]byte
		binary.BigEndian.PutUint64(counter[:], uint64(step))
		mac := hmac.New(sha1.New, seed)
		_, _ = mac.Write(counter[:])
		sum := mac.Sum(nil)
		start := int(sum[len(sum)-1] & 15)
		number := binary.BigEndian.Uint32(sum[start:start+4]) & 0x7fffffff
		expected := fmt.Sprintf("%06d", number%1000000)
		equal := subtle.ConstantTimeCompare([]byte(expected), []byte(code)) == 1
		if equal && step > lastStep && !found {
			matched = step
			found = true
		}
	}

	return matched, found
}
