//! Declarative macro that generates ULID newtypes sharing the same
//! serde/Display/FromStr/Default boilerplate. Each newtype picks its
//! own constructor name so the macro can replace both
//! [`crate::SessionId`] (with `new`) and `rimap_audit::ProcessId`
//! (with `new_now`) without breaking the hundreds of existing call
//! sites.

/// Define a ULID-backed newtype with `serde_transparent`, `Display`,
/// `FromStr` (via `ulid::DecodeError`), `Default`, and a caller-chosen
/// constructor.
///
/// # Usage
///
/// ```ignore
/// rimap_core::ulid_newtype! {
///     /// Per-connection identifier generated on accept.
///     pub struct SessionId;
///     ctor: new;
/// }
/// ```
///
/// The constructor `$ctor` is a `pub fn $ctor() -> Self` that seeds a
/// fresh [`ulid::Ulid`] from the system clock + RNG. `Default::default`
/// forwards to it.
#[macro_export]
macro_rules! ulid_newtype {
    ($(#[$outer:meta])* $vis:vis struct $name:ident; ctor: $ctor:ident $(;)?) => {
        $(#[$outer])*
        #[derive(
            ::core::fmt::Debug,
            ::core::clone::Clone,
            ::core::marker::Copy,
            ::core::cmp::PartialEq,
            ::core::cmp::Eq,
            ::core::hash::Hash,
            ::serde::Serialize,
            ::serde::Deserialize,
        )]
        #[serde(transparent)]
        $vis struct $name(::ulid::Ulid);

        impl $name {
            /// Generate a fresh value from the system clock + randomness.
            #[must_use]
            pub fn $ctor() -> Self {
                Self(::ulid::Ulid::new())
            }

            /// Underlying ULID (escape hatch for interop).
            #[must_use]
            pub fn as_ulid(self) -> ::ulid::Ulid {
                self.0
            }
        }

        impl ::core::default::Default for $name {
            fn default() -> Self {
                Self::$ctor()
            }
        }

        impl ::core::fmt::Display for $name {
            fn fmt(&self, f: &mut ::core::fmt::Formatter<'_>) -> ::core::fmt::Result {
                ::core::fmt::Display::fmt(&self.0, f)
            }
        }

        impl ::core::str::FromStr for $name {
            type Err = ::ulid::DecodeError;
            fn from_str(s: &str) -> ::core::result::Result<Self, Self::Err> {
                ::core::str::FromStr::from_str(s).map(Self)
            }
        }
    };
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "tests")]
mod tests {
    // Macro invocation lives inside the test module so the macro's generated
    // type is confined to tests — no production code touches this newtype.
    crate::ulid_newtype! {
        /// Test-only newtype exercising every trait the macro generates.
        pub(super) struct MacroProbe;
        ctor: new_now;
    }

    use core::str::FromStr;

    #[test]
    fn display_round_trips_via_from_str() {
        let id = MacroProbe::new_now();
        let s = id.to_string();
        assert_eq!(s.len(), 26, "ULID canonical form is 26 chars: {s}");
        let back = MacroProbe::from_str(&s).unwrap();
        assert_eq!(back, id);
    }

    #[test]
    fn default_is_fresh_value() {
        let a = MacroProbe::default();
        let b = MacroProbe::default();
        assert_ne!(a, b, "default() must mint a fresh ULID each call");
    }

    #[test]
    fn serde_transparent_serializes_as_bare_string() {
        let id = MacroProbe::new_now();
        let json = serde_json::to_string(&id).unwrap();
        // The outer braces of a struct would be `{"0":"..."}` — transparent
        // drops them, leaving a bare JSON string. Any drift from bare-string
        // form is an on-disk schema break.
        assert!(json.starts_with('"') && json.ends_with('"'), "{json}");
        let inner = &json[1..json.len() - 1];
        assert_eq!(
            inner.len(),
            26,
            "serialized form must be a raw ULID: {json}"
        );
    }

    #[test]
    fn serde_round_trip_preserves_value() {
        let id = MacroProbe::new_now();
        let json = serde_json::to_string(&id).unwrap();
        let back: MacroProbe = serde_json::from_str(&json).unwrap();
        assert_eq!(back, id);
    }

    #[test]
    fn as_ulid_returns_inner_value() {
        let id = MacroProbe::new_now();
        let inner = id.as_ulid();
        assert_eq!(inner.to_string(), id.to_string());
    }
}
