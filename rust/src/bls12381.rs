use super::*;
use bls12_381_plus::{ExpandMsgXmd, G1Projective, G2Projective, Scalar};
use ff::Field;
use group::Curve;
use rand_core::{CryptoRng, RngCore};
use sha2::Digest;
use std::convert::TryFrom;
use subtle::ConstantTimeEq;

const DST_G1: &[u8] = b"BLS12381G1_XMD:SHA-256_SSWU_RO_";
const DST_G2: &[u8] = b"BLS12381G2_XMD:SHA-256_SSWU_RO_";

pub trait Point:
    std::ops::Mul<Scalar, Output = Self> + std::ops::Add<Self, Output = Self> + Sized
{
    fn generator() -> Self;
    fn hash(msg: &[u8]) -> Self;
    fn to_bytes(&self) -> Vec<u8>;
}

impl Point for G1Projective {
    fn generator() -> Self {
        G1Projective::generator()
    }

    fn hash(msg: &[u8]) -> Self {
        G1Projective::hash::<ExpandMsgXmd<sha2::Sha256>>(msg, DST_G1)
    }

    fn to_bytes(&self) -> Vec<u8> {
        self.to_affine().to_compressed().to_vec()
    }
}

impl Point for G2Projective {
    fn generator() -> Self {
        G2Projective::generator()
    }

    fn hash(msg: &[u8]) -> Self {
        G2Projective::hash::<ExpandMsgXmd<sha2::Sha256>>(msg, DST_G2)
    }

    fn to_bytes(&self) -> Vec<u8> {
        self.to_affine().to_compressed().to_vec()
    }
}

#[derive(Copy, Clone, Debug)]
pub struct Commitment<P: Point>(P);

impl<P: Point> Commitment<P> {
    pub fn new(x: Scalar, r1: Scalar, other: P) -> Self {
        Self(P::generator() * x + other * r1)
    }
}

#[derive(Copy, Clone, Debug)]
pub struct EqProof {
    c: Scalar,
    d: Scalar,
    d1: Scalar,
    d2: Scalar,
}

impl EqProof {
    pub fn new<Q1: Point, Q2: Point, R: RngCore + CryptoRng>(
        x: Scalar,
        r1: Scalar,
        r2: Scalar,
        nonce: Scalar,
        mut rng: R,
    ) -> Self {
        let q1 = Q1::hash(NOTHING_UP_MY_SLEEVE_Q1);
        let q2 = Q2::hash(NOTHING_UP_MY_SLEEVE_Q2);

        let w = Scalar::random(&mut rng);
        let n1 = Scalar::random(&mut rng);
        let n2 = Scalar::random(&mut rng);
        let w1 = Q1::generator() * w + q1 * n1;
        let w2 = Q2::generator() * w + q2 * n2;

        let mut hasher = sha2::Sha384::new();
        hasher.update(w1.to_bytes().as_slice());
        hasher.update(w2.to_bytes().as_slice());
        hasher.update(nonce.to_bytes());
        let hash = <[u8; 48]>::try_from(&hasher.finalize()[..]).unwrap();
        let c = Scalar::from_okm(&hash);
        let d = w - c * x;
        let d1 = n1 - c * r1;
        let d2 = n2 - c * r2;
        Self { c, d, d1, d2 }
    }

    pub fn open<Q1: Point, Q2: Point>(
        &self,
        b: Commitment<Q1>,
        c: Commitment<Q2>,
        nonce: Scalar,
    ) -> bool {
        let q1 = Q1::hash(NOTHING_UP_MY_SLEEVE_Q1);
        let q2 = Q2::hash(NOTHING_UP_MY_SLEEVE_Q2);

        let d1 = Q1::generator() * self.d;
        let d2 = Q2::generator() * self.d;

        let lhs = d1 + q1 * self.d1 + b.0 * self.c;
        let rhs = d2 + q2 * self.d2 + c.0 * self.c;

        let mut hasher = sha2::Sha384::new();
        hasher.update(lhs.to_bytes().as_slice());
        hasher.update(rhs.to_bytes().as_slice());
        hasher.update(nonce.to_bytes());
        let hash = <[u8; 48]>::try_from(&hasher.finalize()[..]).unwrap();
        let c = Scalar::from_okm(&hash);
        self.c.ct_eq(&c).unwrap_u8() == 1
    }
}

#[test]
fn proof_works_both_g1() {
    let mut rng = MockRng::new();
    let x = Scalar::random(&mut rng);
    let r1 = Scalar::random(&mut rng);
    let r2 = Scalar::random(&mut rng);
    let nonce = Scalar::random(&mut rng);

    let q1 = <G1Projective as Point>::hash(NOTHING_UP_MY_SLEEVE_Q1);
    let q2 = <G1Projective as Point>::hash(NOTHING_UP_MY_SLEEVE_Q2);
    let b = Commitment::new(x, r1, q1);
    let c = Commitment::new(x, r2, q2);

    let proof = EqProof::new::<G1Projective, G1Projective, MockRng>(x, r1, r2, nonce, rng);
    assert!(proof.open(b, c, nonce));
}

#[test]
fn proof_works_both_g2() {
    let mut rng = MockRng::new();
    let x = Scalar::random(&mut rng);
    let r1 = Scalar::random(&mut rng);
    let r2 = Scalar::random(&mut rng);
    let nonce = Scalar::random(&mut rng);

    let q1 = <G2Projective as Point>::hash(NOTHING_UP_MY_SLEEVE_Q1);
    let q2 = <G2Projective as Point>::hash(NOTHING_UP_MY_SLEEVE_Q2);
    let b = Commitment::new(x, r1, q1);
    let c = Commitment::new(x, r2, q2);

    let proof = EqProof::new::<G2Projective, G2Projective, MockRng>(x, r1, r2, nonce, rng);
    assert!(proof.open(b, c, nonce));
}

#[test]
fn proof_works_g1_g2() {
    let mut rng = MockRng::new();
    let x = Scalar::random(&mut rng);
    let r1 = Scalar::random(&mut rng);
    let r2 = Scalar::random(&mut rng);
    let nonce = Scalar::random(&mut rng);

    let q1 = <G1Projective as Point>::hash(NOTHING_UP_MY_SLEEVE_Q1);
    let q2 = <G2Projective as Point>::hash(NOTHING_UP_MY_SLEEVE_Q2);
    let b = Commitment::new(x, r1, q1);
    let c = Commitment::new(x, r2, q2);

    let proof = EqProof::new::<G1Projective, G2Projective, MockRng>(x, r1, r2, nonce, rng);
    assert!(proof.open(b, c, nonce));
}

#[test]
fn proof_works_g2_g1() {
    let mut rng = MockRng::new();
    let x = Scalar::random(&mut rng);
    let r1 = Scalar::random(&mut rng);
    let r2 = Scalar::random(&mut rng);
    let nonce = Scalar::random(&mut rng);

    let q1 = <G2Projective as Point>::hash(NOTHING_UP_MY_SLEEVE_Q1);
    let q2 = <G1Projective as Point>::hash(NOTHING_UP_MY_SLEEVE_Q2);
    let b = Commitment::new(x, r1, q1);
    let c = Commitment::new(x, r2, q2);

    let proof = EqProof::new::<G2Projective, G1Projective, MockRng>(x, r1, r2, nonce, rng);
    assert!(proof.open(b, c, nonce));
}

#[cfg(test)]
pub struct MockRng(rand_xorshift::XorShiftRng);

#[cfg(test)]
impl rand_core::CryptoRng for MockRng {}

#[cfg(test)]
impl rand_core::SeedableRng for MockRng {
    type Seed = [u8; 16];

    fn from_seed(seed: Self::Seed) -> Self {
        Self(rand_xorshift::XorShiftRng::from_seed(seed))
    }
}

#[cfg(test)]
impl rand_core::RngCore for MockRng {
    fn next_u32(&mut self) -> u32 {
        self.0.next_u32()
    }

    fn next_u64(&mut self) -> u64 {
        self.0.next_u64()
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        self.0.fill_bytes(dest)
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
        self.0.try_fill_bytes(dest)
    }
}

#[cfg(test)]
impl MockRng {
    pub fn new() -> Self {
        use rand_core::SeedableRng;

        Self::from_seed([7u8; 16])
    }
}
