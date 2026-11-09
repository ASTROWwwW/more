# Style guide

These rules apply to every change. CI checks what a tool can check (format, lints, tests); review checks the rest.

## Formatting and lints

`cargo fmt` with the standard rustfmt settings (`rustfmt.toml` only pins the edition). `cargo clippy --workspace --all-targets -- -D warnings` must pass.

The production crates (`more-identity`, `gpu-ledger`, `gpu-domain`, `gpu-protocol`) opt into the workspace lints in `Cargo.toml`: no `unsafe`, no `unwrap`, `expect`, `panic!`, `todo!`, `unimplemented!` or `dbg!` outside tests. A local `#[allow(...)]` is accepted only with a comment saying why. A global allow that hides a class of warnings is not.

## Naming

Types, traits and enums in `PascalCase`; functions, variables and modules in `snake_case`; constants in `SCREAMING_SNAKE_CASE`. Names say what a thing is in the domain's words (`recovery_earmark`, not `re`). One-letter names are fine for an obvious local index or a closure argument, not for business values.

## Functions

A function does one thing. Aim for 40 to 60 lines. A transition can be longer when splitting it would hide what happens atomically; in that case it reads top to bottom: checks first, then writes. Extract a check that two transitions share. Do not cut a transaction in pieces to meet a line count.

## Errors

Anything that can fail returns `Result` with a typed error that has a stable code (`DomainError::code`, `LedgerApiError::code`, `ProtoError::code`).

- A refused command changes nothing. Do every check before the first write, or run the transition on a copy (`Coordinator::execute` does).
- An internal inconsistency is `DomainError::Internal`, never a panic and never silently skipped. Reconciliation propagates it (JOB-R20).
- Arithmetic on amounts, positions and times uses `checked_*` and returns `Overflow` or `Internal`. `saturating_*` is only for values where clamping is the rule itself, never to hide an overflow.
- Indexing a map with `[]` is acceptable only right after the key was checked or created; otherwise use `get` and return an error.

## Visibility and data ownership

Fields are private. Other code reads through accessors and changes state through transition functions that keep the invariants. Use `pub(crate)` or `pub(super)` for internal interfaces, `pub` only for what another crate needs.

Each trust domain owns its data (see `docs/SECURITY_ARCHITECTURE.md`):

- only `gpu-ledger` writes balances, through `LedgerService::execute`;
- only `more-identity` builds an `AuthContext`, a `VerifiedAccount` or a `ServiceCredential`;
- pools and the catalog change only through `Registry`, delivery state only through `DeliveryBook`.

Never widen visibility to make a test easier. A test that needs to see more uses an accessor or the Auditor role.

## Authorization

Every new command gets a row in the permission matrix (`docs/SECURITY_ARCHITECTURE.md`, section 3), a case in `crates/domain/src/authorization.rs` and the same rule, written independently, in the TEST-P29 oracle (`crates/simulation/src/invariants/security.rs`). Deny by default.

## Documentation

Public items and business functions carry the requirement they implement:

```rust
/// JOB-R17: an output is charged at most once per billing generation.
///
/// # Errors
/// `Internal` if the output is already charged.
```

Comments explain why a rule exists or why the code is shaped this way, not what the next line does. Keep them short.

## Tests

- Unit tests next to the code they test; integration tests in `tests/`.
- An invariant is a property in `crates/simulation/src/invariants/`, checked after every command of every generated trace. New properties take the next free number (TEST-P30 and on); existing numbers never change.
- A fixed bug comes with a test that fails before the fix. A `proptest` counterexample keeps its seed in `tests/properties/proptest-regressions.txt` and gets a reduced, commented test in `tests/regressions/`. These are never deleted.
- Security changes come with a refusal test that checks the state did not change, and, when a boundary is involved, a simulated compromise test.
- Boundary values (zero, `u32::MAX`, `u64::MAX`) for every input that comes from outside.
- When a rule changes, add or update the mutation that would break it (`scripts/mutation.py`).

## Performance

Measure before optimizing and keep the numbers in the change description. The in-memory model clones the whole state per command on purpose (atomicity); do not draw conclusions from it about a PostgreSQL coordinator.

## Architecture principles

Domain modules over technical layers. Explicit state transitions, listed in the spec. Least privilege. Fail closed. Idempotent operations, with business keys that do not depend on transport sequence numbers. Accounting entries are never modified, only reversed. Deterministic tests. Domain, protocol, persistence and simulation stay separate crates or modules.
