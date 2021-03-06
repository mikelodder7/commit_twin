package pkg

import (
	"crypto/rand"
	"github.com/btcsuite/btcd/btcec"
	"testing"
)

func TestNewEqProofK256(t *testing.T) {
	curve := btcec.S256()
	x, _ := rand.Int(rand.Reader, curve.N)
	r1, _ := rand.Int(rand.Reader, curve.N)
	r2, _ := rand.Int(rand.Reader, curve.N)
	nonce, _ := rand.Int(rand.Reader, curve.N)

	q1x, q1y, q2x, q2y := getGenerators()
	b := NewCommitment(x, r1, q1x, q1y)
	c := NewCommitment(x, r2, q2x, q2y)

	proof := NewEqProofK256(x, r1, r2, nonce)
	if !proof.OpenK256(b, c, nonce) {
		t.Fail()
	}
}