use common::prime::GermainSafePrime;
use num_bigint::BigUint;
use num_integer::Integer;
use rayon::prelude::*;

pub struct PublicKey {
    pub n: BigUint,
}

pub struct PrivateKey {
    pub public_key: PublicKey,
    lambda_n: BigUint, // lcm(p-1, q-1)
    phi_n: BigUint,    // (p-1)(q-1)
    p: BigUint,
    q: BigUint,
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
            lambda_n,
            phi_n,
            p,
            q,
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
}

#[cfg(test)]
mod tests {
    use super::*;
    use common::prime::miller_rabin::is_prime;

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
}
