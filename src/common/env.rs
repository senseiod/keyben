//! The environment identifier, shared so the client and the server recognize the same set.

use clap::ValueEnum;

/// Environment identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
#[value(rename_all = "lower")]
pub enum Env {
    Dev,
    Prod,
}

impl Env {
    pub fn as_str(self) -> &'static str {
        match self {
            Env::Dev => "dev",
            Env::Prod => "prod",
        }
    }

    /// Parse the wire form of an environment. The server validates incoming path segments with
    /// this, so the accepted set is defined in exactly one place.
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "dev" => Some(Env::Dev),
            "prod" => Some(Env::Prod),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_round_trips_every_variant_and_rejects_others() {
        for env in [Env::Dev, Env::Prod] {
            assert_eq!(Env::parse(env.as_str()), Some(env));
        }
        for unknown in ["staging", "DEV", "", " dev"] {
            assert_eq!(Env::parse(unknown), None, "{unknown}");
        }
    }
}
