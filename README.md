# recipe-session

`recipe-session` defines generic recipe-backed ingress/egress contract primitives.

This crate intentionally does not parse bytes, open sockets, implement cryptography,
or know about NodePlan. It only validates the contract shape that later layers can
use to negotiate and lock recipe-backed session streams.

Core responsibilities in this pass:

- participants and roles
- recipe references
- recipe/path manifest hashes
- ingress/egress path permissions
- session limits
- receipt policy placeholders
- security policy placeholders
- deterministic canonical contract material

## Releasing

Bump `version` in Cargo.toml, add a dated `## <version> (YYYY-MM-DD)` entry to CHANGELOG.md, and push to
`main`. CI (.github/workflows/ci.yml) runs the tests and clippy, then publishes that version to crates.io.
