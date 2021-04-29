package pkg

import (
	"crypto/rand"
	"crypto/sha512"
	"github.com/btcsuite/btcd/btcec"
	"math/big"
)

var (
	nothingUpMySleeveQ1 = []byte("Cowards die many times before their deaths; The valiant never taste of death but once")
	nothingUpMySleeveQ2 = []byte("Men at some time are masters of their fates")
)

type Commitment struct {
	X *big.Int
	Y *big.Int
}

func NewCommitment(x, r, otherx, othery *big.Int) *Commitment {
	curve := btcec.S256()
	cx, cy := curve.ScalarBaseMult(x.Bytes())
	dx, dy := curve.ScalarMult(otherx, othery, r.Bytes())
	xx, yy := curve.Add(cx, cy, dx, dy)
	return &Commitment{
		xx, yy,
	}
}

type EqProof struct {
	C *big.Int
	D *big.Int
	D1 *big.Int
	D2 *big.Int
}

func NewEqProof(
	x, r1, r2, nonce *big.Int,
	) *EqProof {
	curve := btcec.S256()
	q1x, q1y, q2x, q2y := getGenerators()

	w, _ := rand.Int(rand.Reader, curve.N)
	n1, _ := rand.Int(rand.Reader, curve.N)
	n2, _ := rand.Int(rand.Reader, curve.N)

	w1x1, w1y1 := curve.ScalarBaseMult(w.Bytes())
	w1x2, w1y2 := curve.ScalarMult(q1x, q1y, n1.Bytes())
	w1x, w1y := curve.Add(w1x1, w1y1, w1x2, w1y2)

	w2x2, w2y2 := curve.ScalarMult(q2x, q2y, n2.Bytes())
	w2x, w2y := curve.Add(w1x1, w1y1, w2x2, w2y2)

	hasher := sha512.New()
	_, _ = hasher.Write(w1x.Bytes())
	_, _ = hasher.Write(w1y.Bytes())
	_, _ = hasher.Write(w2x.Bytes())
	_, _ = hasher.Write(w2y.Bytes())
	_, _ = hasher.Write(nonce.Bytes())

	c := new(big.Int).SetBytes(hasher.Sum(nil))
	c.Mod(c, curve.N)

	d := new(big.Int).Sub(w, new(big.Int).Mul(c, x))
	d.Mod(d, curve.N)

	d1 := new(big.Int).Sub(n1, new(big.Int).Mul(c, r1))
	d1.Mod(d1, curve.N)

	d2 := new(big.Int).Sub(n2, new(big.Int).Mul(c, r2))
	d2.Mod(d2, curve.N)

	return &EqProof{
		c, d, d1, d2,
	}
}

func (eq *EqProof) Open(b, c *Commitment, nonce *big.Int) bool {
	curve := btcec.S256()
	q1x, q1y, q2x, q2y := getGenerators()

	dx, dy := curve.ScalarBaseMult(eq.D.Bytes())
	lhsx1, lhsy1 := curve.ScalarMult(q1x, q1y, eq.D1.Bytes())
	lhsx2, lhsy2 := curve.ScalarMult(b.X, b.Y, eq.C.Bytes())
	lhsx1, lhsy1 = curve.Add(dx, dy, lhsx1, lhsy1)
	lhsx, lhsy := curve.Add(lhsx2, lhsy2, lhsx1, lhsy1)

	rhsx1, rhsy1 := curve.ScalarMult(q2x, q2y, eq.D2.Bytes())
	rhsx2, rhsy2 := curve.ScalarMult(c.X, c.Y, eq.C.Bytes())
	rhsx1, rhsy1 = curve.Add(dx, dy, rhsx1, rhsy1)
	rhsx, rhsy := curve.Add(rhsx2, rhsy2, rhsx1, rhsy1)

	hasher := sha512.New()
	_, _ = hasher.Write(lhsx.Bytes())
	_, _ = hasher.Write(lhsy.Bytes())
	_, _ = hasher.Write(rhsx.Bytes())
	_, _ = hasher.Write(rhsy.Bytes())
	_, _ = hasher.Write(nonce.Bytes())

	chal := new(big.Int).SetBytes(hasher.Sum(nil))
	chal.Mod(chal, curve.N)

	return chal.Cmp(eq.C) == 0
}

func getGenerators() (*big.Int, *big.Int, *big.Int, *big.Int) {
	curve := btcec.S256()
	// unsafe method of choosing generator points
	q1sss := sha512.Sum384(nothingUpMySleeveQ1)
	q2sss := sha512.Sum384(nothingUpMySleeveQ2)
	q1ss := new(big.Int).SetBytes(q1sss[:])
	q2ss := new(big.Int).SetBytes(q2sss[:])
	q1s := new(big.Int).Mod(q1ss, curve.N)
	q2s := new(big.Int).Mod(q2ss, curve.N)
	q1x, q1y := curve.ScalarBaseMult(q1s.Bytes())
	q2x, q2y := curve.ScalarBaseMult(q2s.Bytes())

	return q1x, q1y, q2x, q2y
}