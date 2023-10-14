use core::str::FromStr;

const HARDENED_CHAR: char = '\'';
const SIGN_HARDENED: u32 = 1 << 31;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Node {
    Normal(u32),
    Hardened(u32),
}

impl Node {
    pub fn to_hardened(&self) -> Self {
        match self {
            Node::Normal(index) => Node::Hardened(*index),
            _ => *self,
        }
    }

    pub fn is_hardened(&self) -> bool {
        match self {
            Node::Hardened(_) => true,
            _ => false,
        }
    }

    pub fn is_normal(&self) -> bool {
        !self.is_hardened()
    }

    pub fn raw_index(&self) -> u32 {
        match self {
            Node::Hardened(index) => *index + SIGN_HARDENED,
            Node::Normal(index) => *index,
        }
    }
}

impl From<u32> for Node {
    fn from(a: u32) -> Self {
        if (a & SIGN_HARDENED) == 0 {
            Node::Normal(a)
        } else {
            Node::Hardened(a ^ SIGN_HARDENED)
        }
    }
}

impl FromStr for Node {
    type Err = core::num::ParseIntError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (num_str, sign) = match s.strip_suffix(HARDENED_CHAR) {
            Some(a) => (a, SIGN_HARDENED),
            None => (s, 0),
        };
        let num: u32 = num_str.parse()?;
        Ok((sign + num).into())
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn normal_from_u8() {
        assert_eq!(Node::Normal(0), 0_u32.into());
        assert_eq!(Node::Normal(9), 9_u32.into());
        assert_eq!(Node::Normal(123), 123_u32.into());
        assert_eq!(Node::Normal(SIGN_HARDENED - 1), (SIGN_HARDENED - 1).into());
    }

    #[test]
    fn hardened_from_u8() {
        assert_eq!(Node::Hardened(9), (SIGN_HARDENED + 9).into());
        assert_eq!(Node::Hardened(123), (SIGN_HARDENED + 123).into());
        assert_eq!(Node::Hardened(0), SIGN_HARDENED.into());
    }

    #[test]
    fn normal_from_str() {
        assert_eq!(Node::Normal(0), "0".parse().unwrap());
        assert_eq!(Node::Normal(9), "9".parse().unwrap());
        assert_eq!(Node::Normal(123), "123".parse().unwrap());
        assert_eq!(
            Node::Normal(SIGN_HARDENED - 1),
            format!("{}", (SIGN_HARDENED - 1)).parse().unwrap()
        );
    }

    #[test]
    fn hardened_from_str() {
        assert_eq!(Node::Hardened(9), "9'".parse().unwrap());
        assert_eq!(Node::Hardened(0), "0'".parse().unwrap());
        assert_eq!(Node::Hardened(123), "123'".parse().unwrap());
    }
}
