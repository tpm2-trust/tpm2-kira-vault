module github.com/mrwiora/tpm2-kira-vault

go 1.26.0

require (
	github.com/google/go-tpm v0.9.9-0.20261001171150-36f205946d7e
	github.com/mrwiora/tpm2-kira/core v0.0.0
	golang.org/x/sys v0.48.0
)

require golang.org/x/crypto v0.57.0 // indirect

// tpm2-kira's shared core (attest, vaultproto) alone, not tpm2-kira: from
// the submodule tpm2-kira/, the commit it pins (../pin tpm2-kira moves it).
replace github.com/mrwiora/tpm2-kira/core => ./tpm2-kira/core
