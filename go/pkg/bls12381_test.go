package pkg

import (
	"crypto/rand"
	bls12 "github.com/kilic/bls12-381"
	"testing"
)

func TestNewEqProofG1(t *testing.T) {
	g1 := bls12.NewG1()
	x, _ := rand.Int(rand.Reader, g1.Q())
	r1, _ := rand.Int(rand.Reader, g1.Q())
	r2, _ := rand.Int(rand.Reader, g1.Q())
	nonce, _ := rand.Int(rand.Reader, g1.Q())

	q1, _ := g1.HashToCurve(nothingUpMySleeveQ1, dstG1)
	q2, _ := g1.HashToCurve(nothingUpMySleeveQ2, dstG2)

	b := NewCommitmentG1(x, r1, q1)
	c := NewCommitmentG1(x, r2, q2)

	proof := NewEqProofG1(x, r1, r2, nonce)
	if !proof.OpenG1(b, c, nonce) {
		t.Fail()
	}
}
