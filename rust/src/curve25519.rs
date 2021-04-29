use super::*;
use curve25519_dalek::{
    constants::RISTRETTO_BASEPOINT_POINT, ristretto::RistrettoPoint, scalar::Scalar,
};
use rand_core5::{CryptoRng, RngCore};
use sha2::Digest;
use subtle::ConstantTimeEq;

#[derive(Copy, Clone, Debug)]
pub struct Commitment(RistrettoPoint);

impl Commitment {
    pub fn new(x: Scalar, r1: Scalar, other: RistrettoPoint) -> Self {
        Self(RISTRETTO_BASEPOINT_POINT * x + other * r1)
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
    pub fn new<R: RngCore + CryptoRng>(
        x: Scalar,
        r1: Scalar,
        r2: Scalar,
        nonce: Scalar,
        rng: &mut R,
    ) -> Self {
        let q1 = RistrettoPoint::hash_from_bytes::<sha2::Sha512>(NOTHING_UP_MY_SLEEVE_Q1);
        let q2 = RistrettoPoint::hash_from_bytes::<sha2::Sha512>(NOTHING_UP_MY_SLEEVE_Q2);
        let w = Scalar::random(rng);
        let n1 = Scalar::random(rng);
        let n2 = Scalar::random(rng);
        let w1 = RISTRETTO_BASEPOINT_POINT * w + n1 * q1;
        let w2 = RISTRETTO_BASEPOINT_POINT * w + n2 * q2;

        let mut hasher = sha2::Sha512::new();
        hasher.update(w1.compress().as_bytes());
        hasher.update(w2.compress().as_bytes());
        hasher.update(nonce.as_bytes());
        let c = Scalar::from_hash(hasher);
        let d = w - c * x;
        let d1 = n1 - c * r1;
        let d2 = n2 - c * r2;
        Self { c, d, d1, d2 }
    }

    pub fn open(&self, b: Commitment, c: Commitment, nonce: Scalar) -> bool {
        let q1 = RistrettoPoint::hash_from_bytes::<sha2::Sha512>(NOTHING_UP_MY_SLEEVE_Q1);
        let q2 = RistrettoPoint::hash_from_bytes::<sha2::Sha512>(NOTHING_UP_MY_SLEEVE_Q2);

        let d = self.d * RISTRETTO_BASEPOINT_POINT;
        let lhs = d + self.d1 * q1 + self.c * b.0;
        let rhs = d + self.d2 * q2 + self.c * c.0;

        let mut hasher = sha2::Sha512::new();
        hasher.update(lhs.compress().as_bytes());
        hasher.update(rhs.compress().as_bytes());
        hasher.update(nonce.as_bytes());
        let c = Scalar::from_hash(hasher);
        self.c.ct_eq(&c).unwrap_u8() == 1
    }
}

#[cfg(test)]
pub struct MockRng(rand_xorshift2::XorShiftRng);

#[cfg(test)]
impl rand_core5::CryptoRng for MockRng {}

#[cfg(test)]
impl rand_core5::SeedableRng for MockRng {
    type Seed = [u8; 16];

    fn from_seed(seed: Self::Seed) -> Self {
        Self(rand_xorshift2::XorShiftRng::from_seed(seed))
    }
}

#[cfg(test)]
impl rand_core5::RngCore for MockRng {
    fn next_u32(&mut self) -> u32 {
        self.0.next_u32()
    }

    fn next_u64(&mut self) -> u64 {
        self.0.next_u64()
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        self.0.fill_bytes(dest)
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core5::Error> {
        self.0.try_fill_bytes(dest)
    }
}

#[cfg(test)]
impl MockRng {
    pub fn new() -> Self {
        use rand_core5::SeedableRng;

        Self::from_seed([7u8; 16])
    }
}

#[test]
fn proof_works() {
    let mut rng = MockRng::new();
    let x = Scalar::random(&mut rng);
    let r1 = Scalar::random(&mut rng);
    let r2 = Scalar::random(&mut rng);
    let nonce = Scalar::random(&mut rng);

    let q1 = RistrettoPoint::hash_from_bytes::<sha2::Sha512>(NOTHING_UP_MY_SLEEVE_Q1);
    let q2 = RistrettoPoint::hash_from_bytes::<sha2::Sha512>(NOTHING_UP_MY_SLEEVE_Q2);
    let b = Commitment::new(x, r1, q1);
    let c = Commitment::new(x, r2, q2);

    let proof = EqProof::new(x, r1, r2, nonce, &mut rng);
    assert!(proof.open(b, c, nonce));
}
