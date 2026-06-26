package domain

import "testing"

func TestValidWalletName(t *testing.T) {
	good := []string{"vec", "treasury", "petty-cash", "agent_1", "a", "x9"}
	for _, s := range good {
		if !ValidWalletName(s) {
			t.Errorf("ValidWalletName(%q) = false, want true", s)
		}
	}
	bad := []string{
		"",                       // empty
		"-leading",               // starts with hyphen
		"_leading",               // starts with underscore
		"Upper",                  // uppercase
		"has space",              // space
		"a/b",                    // slash
		"a.b",                    // dot
		"a#b",                    // hash
		string(make([]byte, 65)), // too long
	}
	for _, s := range bad {
		if ValidWalletName(s) {
			t.Errorf("ValidWalletName(%q) = true, want false", s)
		}
	}
}

func TestAddressKey(t *testing.T) {
	cases := []struct {
		branch Branch
		index  uint32
		want   string
	}{
		{BranchReceive, 0, "0/0"},
		{BranchReceive, 5, "0/5"},
		{BranchChange, 0, "1/0"},
		{BranchChange, 42, "1/42"},
	}
	for _, tc := range cases {
		if got := AddressKey(tc.branch, tc.index); got != tc.want {
			t.Errorf("AddressKey(%d, %d) = %q, want %q", tc.branch, tc.index, got, tc.want)
		}
	}
}

func TestBranchString(t *testing.T) {
	if BranchReceive.String() != "0" {
		t.Errorf("BranchReceive = %q, want 0", BranchReceive.String())
	}
	if BranchChange.String() != "1" {
		t.Errorf("BranchChange = %q, want 1", BranchChange.String())
	}
}

func TestIndexString(t *testing.T) {
	cases := map[uint32]string{0: "0", 1: "1", 84: "84", 4294967295: "4294967295"}
	for in, want := range cases {
		if got := IndexString(in); got != want {
			t.Errorf("IndexString(%d) = %q, want %q", in, got, want)
		}
	}
}

func TestLooksLikeAddressKey(t *testing.T) {
	good := []string{"0/0", "1/3", "0/4294967295"}
	for _, s := range good {
		if !looksLikeAddressKey(s) {
			t.Errorf("looksLikeAddressKey(%q) = false, want true", s)
		}
	}
	bad := []string{"", "0", "/0", "0/", "0/01", "a/0", "0/b", "00/0"}
	for _, s := range bad {
		if looksLikeAddressKey(s) {
			t.Errorf("looksLikeAddressKey(%q) = true, want false", s)
		}
	}
}
