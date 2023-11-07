use crate::{CommonError, Result};
use num_bigint::{BigInt, BigUint};
use num_modular::{ModularCoreOps, ModularPow, ModularUnaryOps};
use num_traits::{Signed, Zero};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ModInt(BigUint);

impl ModInt {
    pub fn new(module: &BigUint) -> Self {
        Self(module.clone())
    }

    pub fn module(&self) -> &BigUint {
        &self.0
    }

    pub fn add(&self, x: &BigUint, y: &BigUint) -> BigUint {
        x.addm(y, &self.0)
    }

    pub fn sub(&self, x: &BigUint, y: &BigUint) -> BigUint {
        x.subm(y, &self.0)
    }

    pub fn mul(&self, x: &BigUint, y: &BigUint) -> BigUint {
        x.mulm(y, &self.0)
    }

    pub fn div(&self, x: &BigUint, y: &BigUint) -> Result<BigUint> {
        if y.is_zero() {
            return Err(CommonError::division_by_zero());
        }
        let r = x / y;
        let r = r.addm(&BigUint::zero(), &self.0);
        Ok(r)
    }

    pub fn pow(&self, x: &BigUint, y: &BigUint) -> BigUint {
        x.powm(y, &self.0)
    }

    pub fn powi(&self, x: &BigUint, y: &BigInt) -> Result<BigUint> {
        if y.is_negative() {
            let y = y.abs();
            let r = self.pow(x, &y.to_biguint().unwrap());
            let r = self.mod_inverse(&r)?;
            Ok(r)
        } else {
            Ok(self.pow(x, &y.to_biguint().unwrap()))
        }
    }

    pub fn mod_inverse(&self, x: &BigUint) -> Result<BigUint> {
        x.invm(&self.0).ok_or(CommonError::division_by_zero())
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
                m.add(&BigUint::from(x), &BigUint::from(y)),
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
                m.sub(&BigUint::from(x), &BigUint::from(y)),
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
                m.mul(&BigUint::from(x), &BigUint::from(y)),
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
            let r = m.div(&BigUint::from(x), &BigUint::from(y));
            if let Ok(r) = r {
                assert_eq!(r, BigUint::from(expected));
            } else {
                assert_eq!(y, 0);
            }
        };
        check(5, 0, 0);
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
                m.pow(&BigUint::from(x), &BigUint::from(y)),
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
    fn mod_int_powi_positive() {
        let m = ModInt(BigUint::from(10u32));
        let check = |x: u32, y: i32, expected: u32| {
            let a = m.powi(&BigUint::from(x), &BigInt::from(y));
            assert_eq!(a.unwrap(), BigUint::from(expected));
        };
        check(7, 1, 7);
        check(7, 2, 9);
        check(9, 3, 9);
        check(2, 3, 8);
        check(11, 1, 1);
    }

    #[test]
    fn mod_int_powi_negative() {
        let m = ModInt(BigUint::from(10u32));
        let check = |x: u32, y: i32| {
            let a = m.powi(&BigUint::from(x), &BigInt::from(y)).unwrap();
            let b = &a * x.pow(-y as u32) % m.module();
            assert_eq!(b, BigUint::one());
        };
        check(7, -1);
        check(7, -2);
        check(9, -3);
        check(11, -1);
    }

    #[test]
    fn mod_int_powi_zero() {
        let m = ModInt(BigUint::from(10u32));
        let check = |x: u32| {
            let a = m.powi(&BigUint::from(x), &BigInt::from(0)).unwrap();
            assert_eq!(a, BigUint::one());
        };
        check(7);
        check(9);
        check(2);
        check(11);
    }

    #[test]
    fn mod_int_powi_failure() {
        let m = ModInt(BigUint::from(10u32));
        let check = |x: u32, y: i32| {
            let a = m.powi(&BigUint::from(x), &BigInt::from(y));
            assert!(a.is_err());
        };
        check(2, -3);
    }

    #[test]
    fn mod_int_mod_inverse() {
        let m = ModInt(BigUint::from(10u32));
        let check = |x: u32| {
            let r = m.mod_inverse(&BigUint::from(x));
            if let Ok(r) = r {
                let y = m.mul(&r, &BigUint::from(x));
                assert_eq!(y, BigUint::one());
            } else {
                assert!(x == 0 || 10 % x == 0 || x % 2 == 0);
            }
        };
        check(0);
        check(1);
        check(2);
        check(3);
        check(4);
        check(5);
        check(6);
        check(7);
        check(8);
        check(9);
    }
}
