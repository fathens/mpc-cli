use crate::{CryptoError, Result};
use common::mod_int::ModInt;
use common::prime::GermainSafePrime;
use common::random::get_random_positive_relatively_prime_int;
use num_bigint::BigUint;
use num_integer::Integer;
use num_traits::One;
use rayon::prelude::*;

pub struct PublicKey {
    pub n: BigUint,
}

pub struct PrivateKey {
    pub public_key: PublicKey,
    pub p: BigUint,
    pub q: BigUint,
    phi_n: BigUint,    // (p-1)(q-1)
    lambda_n: BigUint, // lcm(p-1, q-1)
}

pub struct EncryptedMessage {
    pub cypher: BigUint,
    pub randomness: BigUint,
}

impl PrivateKey {
    const PQ_BIT_LEN_DIFFERENCE: u64 = 3;

    pub fn generate(mudulus_bit_len: u64) -> Self {
        let (p, q) = Self::gen_pq(mudulus_bit_len / 2);
        let n = &p * &q;
        let q_1 = &q - 1_u8;
        let p_1 = &p - 1_u8;
        let phi_n = &p_1 * &q_1;
        let lambda_n = &phi_n / &p_1.gcd(&q_1);

        Self {
            public_key: PublicKey { n },
            p,
            q,
            phi_n,
            lambda_n,
        }
    }

    fn gen_pq(bit_len: u64) -> (BigUint, BigUint) {
        let min_sub = bit_len - Self::PQ_BIT_LEN_DIFFERENCE;
        const CONCURRENT_NUM: usize = 100;
        (0..)
            .find_map(|_| {
                (0..CONCURRENT_NUM)
                    .into_par_iter()
                    .map(|_| {
                        let p = GermainSafePrime::generate(bit_len).safe_prime;
                        let q = GermainSafePrime::generate(bit_len).safe_prime;
                        if p > q {
                            (p, q)
                        } else {
                            (q, p)
                        }
                    })
                    .find_any(|(p, q)| (p - q).bits() >= min_sub)
            })
            .unwrap()
    }

    pub fn decrypt(&self, c: &BigUint) -> Result<BigUint> {
        let n2 = ModInt::new(&(&self.public_key.n * &self.public_key.n));
        if c >= n2.module() {
            return Err(CryptoError::message_too_long());
        }
        if c.gcd(n2.module()) > One::one() {
            return Err(CryptoError::message_malformed());
        }

        let lcalc = |a| -> BigUint {
            let x = n2.pow(a, &self.lambda_n) - 1_u8;
            x / &self.public_key.n
        };

        let lc = lcalc(c);
        let lg = lcalc(&(&self.public_key.n + 1_u8));
        let mod_n = ModInt::new(&self.public_key.n);
        let inv = mod_n.mod_inverse(&lg)?;
        Ok(mod_n.mul(&lc, &inv))
    }
}

impl PublicKey {
    pub fn encrypt(&self, m: &BigUint) -> Result<EncryptedMessage> {
        if m >= &self.n {
            return Err(CryptoError::message_too_long());
        }
        let mut rnd = rand::thread_rng();
        let x = get_random_positive_relatively_prime_int(&mut rnd, &self.n)?;
        let n2 = ModInt::new(&(&self.n * &self.n));
        let gm = n2.pow(&(&self.n + 1_u8), m);
        let xn = n2.pow(&x, &self.n);
        let c = n2.mul(&gm, &xn);
        Ok(EncryptedMessage {
            cypher: c,
            randomness: x,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use common::prime::miller_rabin::is_prime;
    use num_bigint::RandBigInt;

    #[test]
    fn private_key_generate() {
        const BIT_LEN: u64 = 512;
        let sk = PrivateKey::generate(BIT_LEN * 2);
        assert!(is_prime(&sk.p, None));
        assert!(is_prime(&sk.q, None));
        assert_eq!(sk.p.bits(), BIT_LEN);
        assert_eq!(sk.q.bits(), BIT_LEN);
        assert_ne!(sk.p, sk.q);
        assert!((&sk.p - &sk.q).bits() >= BIT_LEN - PrivateKey::PQ_BIT_LEN_DIFFERENCE);
        assert_eq!(sk.public_key.n, &sk.p * &sk.q);
        assert_eq!(sk.phi_n, (&sk.p - 1_u8) * (&sk.q - 1_u8));
    }

    #[test]
    fn encrypt_decrypt() {
        const BIT_LEN: u64 = 512;
        let sk = PrivateKey::generate(BIT_LEN * 2);
        let mut rnd = rand::thread_rng();
        let mut m = rnd.gen_biguint(BIT_LEN);
        m.set_bit(BIT_LEN - 1, true);
        let encrypted = sk.public_key.encrypt(&m).unwrap();
        let m2 = sk.decrypt(&encrypted.cypher).unwrap();
        assert_eq!(m, m2);
    }

    #[test]
    fn encrypt_failure() {
        const BIT_LEN: u64 = 128;
        let sk = PrivateKey::generate(BIT_LEN * 2);
        let m = BigUint::one() << (BIT_LEN * 2);
        assert!(sk.public_key.encrypt(&m).is_err());
    }
}
