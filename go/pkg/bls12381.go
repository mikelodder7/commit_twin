package pkg

import (
	"crypto/rand"
	"crypto/sha512"
	bls12 "github.com/kilic/bls12-381"
	"math/big"
)

type CommitmentG1 struct {
	Value *bls12.PointG1
}

type CommitmentG2 struct {
	 Value *bls12.PointG2
}

func NewCommitmentG1(x, r *big.Int, other *bls12.PointG1) *CommitmentG1 {
	g1 := bls12.NewG1()
	result := g1.New()
	rhs := g1.New()

	g1.MulScalarBig(result, g1.One(), x)
	g1.MulScalarBig(rhs, other, r)
	g1.Add(result, result, rhs)

	return &CommitmentG1{
		result,
	}
}

func NewCommitmentG2(x, r *big.Int, other *bls12.PointG2) *CommitmentG2 {
	g2 := bls12.NewG2()
	result := g2.New()
	rhs := g2.New()

	g2.MulScalarBig(result, g2.One(), x)
	g2.MulScalarBig(rhs, other, r)
	g2.Add(result, result, rhs)

	return &CommitmentG2{
		result,
	}
}

func NewEqProofG1(
	x, r1, r2, nonce *big.Int,
) *EqProof {
	g1 := bls12.NewG1()

	w, _ := rand.Int(rand.Reader, g1.Q())
	n1, _ := rand.Int(rand.Reader, g1.Q())
	n2, _ := rand.Int(rand.Reader, g1.Q())

	q1, _ := g1.HashToCurve(nothingUpMySleeveQ1, dstG1)
	q2, _ := g1.HashToCurve(nothingUpMySleeveQ2, dstG1)

	w1 := g1.New()
	w1Tmp := g1.New()
	g1.MulScalarBig(w1, g1.One(), w)
	g1.MulScalarBig(w1Tmp, q1, n1)
	g1.Add(w1, w1, w1Tmp)

	w2 := g1.New()
	w2Tmp := g1.New()
	g1.MulScalarBig(w2, g1.One(), w)
	g1.MulScalarBig(w2Tmp, q2, n2)
	g1.Add(w2, w2, w2Tmp)

	hasher := sha512.New384()
	_, _ = hasher.Write(g1.ToCompressed(w1))
	_, _ = hasher.Write(g1.ToCompressed(w2))
	_, _ = hasher.Write(nonce.Bytes())

	c := new(big.Int).SetBytes(hasher.Sum(nil))
	c.Mod(c, g1.Q())

	d := new(big.Int).Sub(w, new(big.Int).Mul(c, x))
	d.Mod(d, g1.Q())

	d1 := new(big.Int).Sub(n1, new(big.Int).Mul(c, r1))
	d1.Mod(d1, g1.Q())

	d2 := new(big.Int).Sub(n2, new(big.Int).Mul(c, r2))
	d2.Mod(d2, g1.Q())

	return &EqProof{
		c, d, d1, d2,
	}
}

func NewEqProofG2(
	x, r1, r2, nonce *big.Int,
) *EqProof {
	g2 := bls12.NewG2()

	w, _ := rand.Int(rand.Reader, g2.Q())
	n1, _ := rand.Int(rand.Reader, g2.Q())
	n2, _ := rand.Int(rand.Reader, g2.Q())

	q1, _ := g2.HashToCurve(nothingUpMySleeveQ1, dstG2)
	q2, _ := g2.HashToCurve(nothingUpMySleeveQ2, dstG2)

	w1 := g2.New()
	w1Tmp := g2.New()
	g2.MulScalarBig(w1, g2.One(), w)
	g2.MulScalarBig(w1Tmp, q1, n1)
	g2.Add(w1, w1, w1Tmp)

	w2 := g2.New()
	w2Tmp := g2.New()
	g2.MulScalarBig(w2, g2.One(), w)
	g2.MulScalarBig(w2Tmp, q2, n2)
	g2.Add(w2, w2, w2Tmp)

	hasher := sha512.New384()
	_, _ = hasher.Write(g2.ToCompressed(w1))
	_, _ = hasher.Write(g2.ToCompressed(w2))
	_, _ = hasher.Write(nonce.Bytes())

	c := new(big.Int).SetBytes(hasher.Sum(nil))
	c.Mod(c, g2.Q())

	d := new(big.Int).Sub(w, new(big.Int).Mul(c, x))
	d.Mod(d, g2.Q())

	d1 := new(big.Int).Sub(n1, new(big.Int).Mul(c, r1))
	d1.Mod(d1, g2.Q())

	d2 := new(big.Int).Sub(n2, new(big.Int).Mul(c, r2))
	d2.Mod(d2, g2.Q())

	return &EqProof{
		c, d, d1, d2,
	}
}

func NewEqProofG1G2(
	x, r1, r2, nonce *big.Int,
	) *EqProof {

	g1 := bls12.NewG1()
	g2 := bls12.NewG2()

	w, _ := rand.Int(rand.Reader, g1.Q())
	n1, _ := rand.Int(rand.Reader, g1.Q())
	n2, _ := rand.Int(rand.Reader, g2.Q())

	q1, _ := g1.HashToCurve(nothingUpMySleeveQ1, dstG1)
	q2, _ := g2.HashToCurve(nothingUpMySleeveQ2, dstG2)

	w1 := g1.New()
	w1Tmp := g1.New()
	g1.MulScalarBig(w1, g1.One(), w)
	g1.MulScalarBig(w1Tmp, q1, n1)
	g1.Add(w1, w1, w1Tmp)

	w2 := g2.New()
	w2Tmp := g2.New()
	g2.MulScalarBig(w2, g2.One(), w)
	g2.MulScalarBig(w2Tmp, q2, n2)
	g2.Add(w2, w2, w2Tmp)

	hasher := sha512.New384()
	_, _ = hasher.Write(g1.ToCompressed(w1))
	_, _ = hasher.Write(g2.ToCompressed(w2))
	_, _ = hasher.Write(nonce.Bytes())

	c := new(big.Int).SetBytes(hasher.Sum(nil))
	c.Mod(c, g1.Q())

	d := new(big.Int).Sub(w, new(big.Int).Mul(c, x))
	d.Mod(d, g1.Q())

	d1 := new(big.Int).Sub(n1, new(big.Int).Mul(c, r1))
	d1.Mod(d1, g1.Q())

	d2 := new(big.Int).Sub(n2, new(big.Int).Mul(c, r2))
	d2.Mod(d2, g1.Q())

	return &EqProof{
		c, d, d1, d2,
	}
}

func NewEqProofG2G1(
	x, r1, r2, nonce *big.Int,
) *EqProof {
	g1 := bls12.NewG1()
	g2 := bls12.NewG2()

	w, _ := rand.Int(rand.Reader, g1.Q())
	n1, _ := rand.Int(rand.Reader, g2.Q())
	n2, _ := rand.Int(rand.Reader, g1.Q())

	q1, _ := g2.HashToCurve(nothingUpMySleeveQ1, dstG2)
	q2, _ := g1.HashToCurve(nothingUpMySleeveQ2, dstG1)

	w1 := g2.New()
	w1Tmp := g2.New()
	g2.MulScalarBig(w1, g2.One(), w)
	g2.MulScalarBig(w1Tmp, q1, n1)
	g2.Add(w1, w1, w1Tmp)

	w2 := g1.New()
	w2Tmp := g1.New()
	g1.MulScalarBig(w2, g1.One(), w)
	g1.MulScalarBig(w2Tmp, q2, n2)
	g1.Add(w2, w2, w2Tmp)

	hasher := sha512.New384()
	_, _ = hasher.Write(g2.ToCompressed(w1))
	_, _ = hasher.Write(g1.ToCompressed(w2))
	_, _ = hasher.Write(nonce.Bytes())

	c := new(big.Int).SetBytes(hasher.Sum(nil))
	c.Mod(c, g1.Q())

	d := new(big.Int).Sub(w, new(big.Int).Mul(c, x))
	d.Mod(d, g1.Q())

	d1 := new(big.Int).Sub(n1, new(big.Int).Mul(c, r1))
	d1.Mod(d1, g1.Q())

	d2 := new(big.Int).Sub(n2, new(big.Int).Mul(c, r2))
	d2.Mod(d2, g1.Q())

	return &EqProof{
		c, d, d1, d2,
	}
}

func (eq *EqProof) OpenG1(b, c *CommitmentG1, nonce *big.Int) bool {
	g1 := bls12.NewG1()
	q1, _ := g1.HashToCurve(nothingUpMySleeveQ1, dstG1)
	q2, _ := g1.HashToCurve(nothingUpMySleeveQ2, dstG1)

	d := g1.New()

	g1.MulScalarBig(d, g1.One(), eq.D)

	lhs := g1.New()
	lhsTmp := g1.New()
	g1.MulScalarBig(lhs, q1, eq.D1)
	g1.MulScalarBig(lhsTmp, b.Value, eq.C)
	g1.Add(lhs, lhs, d)
	g1.Add(lhs, lhs, lhsTmp)


	rhs := g1.New()
	rhsTmp := g1.New()
	g1.MulScalarBig(rhs, q2, eq.D2)
	g1.MulScalarBig(rhsTmp, c.Value, eq.C)
	g1.Add(rhs, rhs, d)
	g1.Add(rhs, rhs, rhsTmp)

	hasher := sha512.New384()
	_, _ = hasher.Write(g1.ToCompressed(lhs))
	_, _ = hasher.Write(g1.ToCompressed(rhs))
	_, _ = hasher.Write(nonce.Bytes())

	chal := new(big.Int).SetBytes(hasher.Sum(nil))
	chal.Mod(chal, g1.Q())

	return chal.Cmp(eq.C) == 0
}

func (eq *EqProof) OpenG2(b, c *CommitmentG2, nonce *big.Int) bool {
	g2 := bls12.NewG2()
	q1, _ := g2.HashToCurve(nothingUpMySleeveQ1, dstG2)
	q2, _ := g2.HashToCurve(nothingUpMySleeveQ2, dstG2)

	d := g2.New()

	g2.MulScalarBig(d, g2.One(), eq.D)

	lhs := g2.New()
	lhsTmp := g2.New()
	g2.MulScalarBig(lhs, q1, eq.D1)
	g2.MulScalarBig(lhsTmp, b.Value, eq.C)
	g2.Add(lhs, lhs, d)
	g2.Add(lhs, lhs, lhsTmp)


	rhs := g2.New()
	rhsTmp := g2.New()
	g2.MulScalarBig(rhs, q2, eq.D2)
	g2.MulScalarBig(rhsTmp, c.Value, eq.C)
	g2.Add(rhs, rhs, d)
	g2.Add(rhs, rhs, rhsTmp)

	hasher := sha512.New384()
	_, _ = hasher.Write(g2.ToCompressed(lhs))
	_, _ = hasher.Write(g2.ToCompressed(rhs))
	_, _ = hasher.Write(nonce.Bytes())

	chal := new(big.Int).SetBytes(hasher.Sum(nil))
	chal.Mod(chal, g2.Q())

	return chal.Cmp(eq.C) == 0
}

func (eq *EqProof) OpenG1G2(b *CommitmentG1, c *CommitmentG2, nonce *big.Int) bool {
	g1 := bls12.NewG1()
	g2 := bls12.NewG2()
	q1, _ := g1.HashToCurve(nothingUpMySleeveQ1, dstG1)
	q2, _ := g2.HashToCurve(nothingUpMySleeveQ2, dstG2)

	dG1 := g1.New()
	dG2 := g2.New()

	g1.MulScalarBig(dG1, g1.One(), eq.D)
	g2.MulScalarBig(dG2, g2.One(), eq.D)

	lhs := g1.New()
	lhsTmp := g1.New()
	g1.MulScalarBig(lhs, q1, eq.D1)
	g1.MulScalarBig(lhsTmp, b.Value, eq.C)
	g1.Add(lhs, lhs, dG1)
	g1.Add(lhs, lhs, lhsTmp)


	rhs := g2.New()
	rhsTmp := g2.New()
	g2.MulScalarBig(rhs, q2, eq.D2)
	g2.MulScalarBig(rhsTmp, c.Value, eq.C)
	g2.Add(rhs, rhs, dG2)
	g2.Add(rhs, rhs, rhsTmp)

	hasher := sha512.New384()
	_, _ = hasher.Write(g1.ToCompressed(lhs))
	_, _ = hasher.Write(g2.ToCompressed(rhs))
	_, _ = hasher.Write(nonce.Bytes())

	chal := new(big.Int).SetBytes(hasher.Sum(nil))
	chal.Mod(chal, g1.Q())

	return chal.Cmp(eq.C) == 0
}

func (eq *EqProof) OpenG2G1(b *CommitmentG2, c *CommitmentG1, nonce *big.Int) bool {
	g1 := bls12.NewG1()
	g2 := bls12.NewG2()

	q1, _ := g2.HashToCurve(nothingUpMySleeveQ1, dstG2)
	q2, _ := g1.HashToCurve(nothingUpMySleeveQ2, dstG1)

	dG1 := g1.New()
	dG2 := g2.New()

	g1.MulScalarBig(dG1, g1.One(), eq.D)
	g2.MulScalarBig(dG2, g2.One(), eq.D)

	lhs := g2.New()
	lhsTmp := g2.New()
	g2.MulScalarBig(lhs, q1, eq.D1)
	g2.MulScalarBig(lhsTmp, b.Value, eq.C)
	g2.Add(lhs, lhs, dG2)
	g2.Add(lhs, lhs, lhsTmp)


	rhs := g1.New()
	rhsTmp := g1.New()
	g1.MulScalarBig(rhs, q2, eq.D2)
	g1.MulScalarBig(rhsTmp, c.Value, eq.C)
	g1.Add(rhs, rhs, dG1)
	g1.Add(rhs, rhs, rhsTmp)

	hasher := sha512.New384()
	_, _ = hasher.Write(g2.ToCompressed(lhs))
	_, _ = hasher.Write(g1.ToCompressed(rhs))
	_, _ = hasher.Write(nonce.Bytes())

	chal := new(big.Int).SetBytes(hasher.Sum(nil))
	chal.Mod(chal, g2.Q())

	return chal.Cmp(eq.C) == 0
}