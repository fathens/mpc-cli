use num_bigint::{BigUint, RandBigInt};

pub fn generate<F, const N: usize>(mut f: F) -> [BigUint; N]
where
    F: FnMut(u8) -> BigUint,
{
    let mut bs = Vec::with_capacity(N);
    for i in 0..N {
        bs.push(f(i as u8));
    }
    bs.try_into().unwrap()
}

pub fn gen_random<const N: usize>(celling: &BigUint) -> [BigUint; N] {
    generate(|_| rand::thread_rng().gen_biguint_below(celling))
}

pub fn convert<F, const N: usize>(bs: &[BigUint; N], mut f: F) -> [BigUint; N]
where
    F: FnMut(u8, &BigUint) -> BigUint,
{
    generate(|i| f(i, &bs[i as usize]))
}
