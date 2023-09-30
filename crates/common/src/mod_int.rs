use num_bigint::BigUint;
use num_modular::{ModularAbs, ModularCoreOps, ModularPow, ModularUnaryOps};
use num_traits::Zero;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ModInt(BigUint);

impl ModInt {
    pub fn add(&self, x: BigUint, y: BigUint) -> BigUint {
        x.addm(&y, &self.0)
    }

    pub fn sub(&self, x: BigUint, y: BigUint) -> BigUint {
        x.subm(&y, &self.0)
    }

    pub fn mul(&self, x: BigUint, y: BigUint) -> BigUint {
        x.mulm(&y, &self.0)
    }

    pub fn div(&self, x: BigUint, y: BigUint) -> BigUint {
        let r = x / y;
        r.addm(&BigUint::zero(), &self.0)
    }

    pub fn pow(&self, x: BigUint, y: BigUint) -> BigUint {
        x.powm(&y, &self.0)
    }

    pub fn mod_inverse(&self, x: BigUint) -> BigUint {
        x.invm(&self.0).unwrap()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use num_traits::One;

    #[test]
    fn mod_int_add() {
        let m = ModInt(BigUint::from(10u32));
        let check = |x: u32, y: u32, expected: u32| {
            assert_eq!(
                m.add(BigUint::from(x), BigUint::from(y)),
                BigUint::from(expected)
            );
        };
        check(0, 0, 0);
        check(1, 2, 3);
        check(9, 8, 7);
        check(4, 6, 0);
        check(11, 1, 2);
    }

    #[test]
    fn mod_int_sub() {
        let m = ModInt(BigUint::from(10u32));
        let check = |x: u32, y: u32, expected: u32| {
            assert_eq!(
                m.sub(BigUint::from(x), BigUint::from(y)),
                BigUint::from(expected)
            );
        };
        check(0, 0, 0);
        check(1, 2, 9);
        check(9, 8, 1);
        check(4, 6, 8);
        check(3, 49, 4);
        check(11, 1, 0);
    }

    #[test]
    fn mod_int_mul() {
        let m = ModInt(BigUint::from(10u32));
        let check = |x: u32, y: u32, expected: u32| {
            assert_eq!(
                m.mul(BigUint::from(x), BigUint::from(y)),
                BigUint::from(expected)
            );
        };
        check(0, 0, 0);
        check(1, 2, 2);
        check(9, 8, 2);
        check(4, 6, 4);
        check(11, 1, 1);
    }

    #[test]
    fn mod_int_div() {
        let m = ModInt(BigUint::from(10u32));
        let check = |x: u32, y: u32, expected: u32| {
            assert_eq!(
                m.div(BigUint::from(x), BigUint::from(y)),
                BigUint::from(expected)
            );
        };
        check(7, 1, 7);
        check(7, 2, 3);
        check(9, 3, 3);
        check(2, 3, 0);
        check(11, 1, 1);
    }

    #[test]
    fn mod_int_pow() {
        let m = ModInt(BigUint::from(10u32));
        let check = |x: u32, y: u32, expected: u32| {
            assert_eq!(
                m.pow(BigUint::from(x), BigUint::from(y)),
                BigUint::from(expected)
            );
        };
        check(7, 1, 7);
        check(7, 2, 9);
        check(9, 3, 9);
        check(2, 3, 8);
        check(11, 1, 1);
    }

    #[test]
    fn mod_int_mod_inverse() {
        let m = ModInt(BigUint::from(10u32));
        let check = |x: u32| {
            let r = m.mod_inverse(BigUint::from(x));
            let y = m.mul(r, BigUint::from(x));
            assert_eq!(y, BigUint::one());
        };
        check(1);
        check(3);
        check(7);
        check(9);
    }
}
