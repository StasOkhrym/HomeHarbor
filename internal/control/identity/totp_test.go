package identity

import (
	"testing"
	"time"
)

func TestTOTPMatchesRFC6238SixDigitVectors(t *testing.T) {
	seed := []byte("12345678901234567890")
	for _, tc := range []struct {
		unix, step int64
		code       string
	}{
		{59, 1, "287082"}, {1111111109, 37037036, "081804"}, {1111111111, 37037037, "050471"}, {1234567890, 41152263, "005924"}, {2000000000, 66666666, "279037"}, {20000000000, 666666666, "353130"},
	} {
		if step, ok := matchingTOTPStep(
			seed,
			tc.code,
			time.Unix(tc.unix, 0),
			-1,
		); !ok ||
			step != tc.step {
			t.Fatalf("RFC timestamp%d code%s: step%d valid%v", tc.unix, tc.code, step, ok)
		}
	}
}

func TestTOTPWindowAndReplay(t *testing.T) {
	seed := []byte("12345678901234567890")
	for _, tc := range []struct {
		unix, last int64
		code       string
		want       bool
	}{
		{59, -1, "755224", true},
		{59, -1, "287082", true},
		{59, -1, "359152", true},
		{59, 1, "287082", false},
		{90, -1, "287082", false},
		{0, -1, "359152", false},
		{59, -1, "28708", false},
		{59, -1, " 287082", false},
		{59, -1, "２８７０８２", false},
		{-1, -1, "755224", false},
	} {
		_, ok := matchingTOTPStep(seed, tc.code, time.Unix(tc.unix, 0), tc.last)

		if ok != tc.want {
			t.Fatalf("window/replay admission at%d last%d code%q=%v", tc.unix, tc.last, tc.code, ok)
		}
	}
}
