package admin

import "testing"

func TestHashAndVerifyPassword(t *testing.T) {
	hash, err := HashPassword("a-long-test-password")
	if err != nil {
		t.Fatal(err)
	}

	if !VerifyPassword(hash, "a-long-test-password") {
		t.Fatal("expected password to verify")
	}

	if VerifyPassword(hash, "wrong-password") {
		t.Fatal("wrong password unexpectedly verified")
	}
}
