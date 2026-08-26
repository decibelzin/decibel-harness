//! Opaque string-branded identifiers.
//!
//! These are newtypes over `String` so a session id can never be passed where
//! a message id is expected. They serialize transparently as plain strings, so
//! the durable JSON form is identical to a bare string.

use serde::{Deserialize, Serialize};

/// Macro defining a transparent `String` newtype id with the common surface.
macro_rules! string_id {
    ($(#[$meta:meta])* $name:ident) => {
        $(#[$meta])*
        #[derive(Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
        #[serde(transparent)]
        pub struct $name(pub String);

        impl $name {
            /// Borrow the underlying string.
            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl From<String> for $name {
            fn from(value: String) -> Self {
                $name(value)
            }
        }

        impl From<&str> for $name {
            fn from(value: &str) -> Self {
                $name(value.to_owned())
            }
        }

        impl std::fmt::Display for $name {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str(&self.0)
            }
        }

        impl std::fmt::Debug for $name {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                write!(f, "{}({:?})", stringify!($name), self.0)
            }
        }
    };
}

string_id! {
    /// Identifies one session and its persistence artifacts.
    SessionId
}

string_id! {
    /// Stable identity of one `Message`, minted at creation.
    MessageId
}

string_id! {
    /// Provider-issued tool-call id pairing a call with its result.
    CallId
}
