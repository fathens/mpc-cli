use core::str::FromStr;

use super::node::Node;

const ROOT_CHAR: char = 'm';
const PATH_SEPARATOR: char = '/';

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct HDPathError {
    reason: String,
}

impl std::fmt::Display for HDPathError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.reason.fmt(f)
    }
}

impl From<<Node as FromStr>::Err> for HDPathError {
    fn from(src: <Node as FromStr>::Err) -> Self {
        Self {
            reason: src.to_string(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct HDPath(Vec<Node>);

impl HDPath {
    #[inline]
    pub fn nodes(&self) -> &[Node] {
        &self.0
    }
}

impl TryFrom<Vec<Node>> for HDPath {
    type Error = HDPathError;

    fn try_from(ps: Vec<Node>) -> Result<Self, Self::Error> {
        if ps.is_empty() {
            return Err(HDPathError {
                reason: "empty path".to_owned(),
            });
        }
        Ok(HDPath(ps))
    }
}

impl FromStr for HDPath {
    type Err = HDPathError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if let Some(a) = s.strip_prefix(ROOT_CHAR) {
            if let Some(b) = a.strip_prefix(PATH_SEPARATOR) {
                let ps = split(b)?;
                return ps.try_into();
            }
        }
        Err(HDPathError {
            reason: format!("should start with '{ROOT_CHAR}'"),
        })
    }
}

fn split(s: &str) -> Result<Vec<Node>, <Node as FromStr>::Err> {
    s.split(PATH_SEPARATOR).map(Node::from_str).collect()
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn from_vec() {
        let ps1 = vec![Node::from(1), Node::from(2), Node::from(3), Node::from(4)];
        assert_eq!(HDPath(ps1.clone()), ps1.try_into().unwrap());

        let ps2 = vec![
            Node::from(1).to_hardened(),
            Node::from(2).to_hardened(),
            Node::from(3),
        ];
        assert_eq!(HDPath(ps2.clone()), ps2.try_into().unwrap());

        assert_eq!(None::<HDPath>, vec![].try_into().ok());
    }

    #[test]
    fn parse_str() {
        let ps1 = vec![Node::from(1), Node::from(2), Node::from(3), Node::from(4)];
        assert_eq!(HDPath(ps1), "m/1/2/3/4".parse().unwrap());

        let ps2 = vec![
            Node::from(1).to_hardened(),
            Node::from(2).to_hardened(),
            Node::from(3),
        ];
        assert_eq!(HDPath(ps2), "m/1'/2'/3".parse().unwrap());

        assert_eq!(None::<HDPath>, "/m/1/2/3".parse().ok());
        assert_eq!(None::<HDPath>, "m/1/2/3/".parse().ok());
        assert_eq!(None::<HDPath>, "1/m/2/3".parse().ok());
        assert_eq!(None::<HDPath>, "m//1/2/3".parse().ok());
        assert_eq!(None::<HDPath>, "m".parse().ok());
        assert_eq!(None::<HDPath>, "m/".parse().ok());
        assert_eq!(None::<HDPath>, "".parse().ok());
    }
}
