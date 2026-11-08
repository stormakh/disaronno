# Porting contract

This repo is a Rust port of Baileys. `upstream/` is the TypeScript source. It is read-only.

The goals: pass at least 95% of the upstream Jest tests, run 10X faster than Node, use less memory.

## Commands

Run from the repo root. `upstream/` and `lust-lang/` are local clones (see README). In a git worktree, use the absolute paths of the main checkout for them.

```sh
mise exec -- cargo test -p baileys --test <suite>        # one ported suite
node scripts/score.mjs                                   # score against the ledger
mise exec -- lust-lang/target/release/lust check crates/baileys/src/lib.rs --manifest-path crates/baileys/Cargo.toml --lib --no-default-features
```

Every change must pass both compilers. `lust` is the required dev compiler. `cargo build --release` makes the shipped binary.

## Language limits, because lust must compile `crates/baileys/src`

- No `async`, no proc macros, no serde, no `dyn` of std traits other than `Fn`, `Any`, `Error`, `Debug`, `Display`.
- No `unsafe` outside code gated by `#[cfg(feature = "native")]`. Code gated that way needs a `#[cfg(not(feature = "native"))]` version with the same behavior.
- No `impl Trait` inside another type, such as `Vec<impl Fn()>`.
- No new crates without a real need. A crate must have a lust adapter (`lust-lang/library/deps`) or be optional behind the `native` feature.
- Lust has a stricter lifetime model than rustc. If it rejects a closure that stores a borrowed argument, use a small iterator or a plain loop. `tests/` files only need Cargo.

Upstream `async` functions become plain blocking functions. Promises become return values. Callbacks and mocks become `Box<dyn Fn>` or closures that record their calls.

## Foundations already in place. Read these first

- `crates/waproto`: generated protobuf types. Regenerate with `node scripts/protogen.mjs`. Do not edit `generated.rs`.
  - A message stores only the fields that are set. Use accessors, not fields:
    `m.push_name()` returns `Option<&Str>`, `m.message_timestamp()` returns `Option<u64>`, `m.key()` returns `Option<&MessageKey>`, a repeated field returns a slice.
    `m.set_push_name(v)`, `m.with_push_name(v)` (builder), `m.clear_push_name()`, `m.key_mut()` (sets the default first when not set).
  - Field names are snake_case. Reserved words use `r#`: `hello.r#static()`.
  - Nested types are in a snake_case module: `proto::message::ImageMessage`, `proto::web_message_info::StubType`.
  - Enums are structs over `i32`, with constants: `proto::history_sync::HistorySyncType::RECENT`, `.0` for the number, `.name()`.
  - `PbMessage` gives `encode()`, `decode(&[u8])`, `decode_shared(Arc<Vec<u8>>)`, `to_json()`, `from_json(&Json)`. `to_json` matches protobufjs `toJSON`. `from_json` matches `fromObject`.
  - `pb::Str` and `pb::Bytes` are cheap to clone and store short values inline. `pb::Json` keeps object order. `pb::base64_encode`, `pb::base64_decode`.
- `crates/baileys/src/wabinary`: `BinaryNode`, `Attrs`, `Content`, encode, decode, JID helpers. `Attrs::from([("a", "b")])`.
- `crates/baileys/src/crypto`: every primitive in `Utils/crypto.ts` and libsignal.
- `crates/baileys/src/signal`: sessions, sender keys, LID mapping, repository.
- `crates/baileys/src/auth.rs`: `SignalKeyStore`, `KeyKind`, `KeyValue`, `MemoryKeyStore`.
- `crates/baileys/src/utils/noise.rs`, `utils/lt_hash.rs`, `utils/time.rs`.
- `crates/baileys/src/error.rs`: `Boom`, `Result`.

Add to these when needed. Keep such changes small, because other agents use them too.

## Porting tests

`tests-data/ledger.json` lists all 407 upstream tests from the real Jest run. Each entry has `suite`, `file`, `name`, `fullName`.

- The test for an entry lives in `crates/baileys/tests/<file>.rs`, in a `#[test] fn <name>()`, with exactly that name. `scripts/score.mjs` matches on it.
- Read the upstream test in `upstream/src/__tests__/<suite>.test.ts` and port every assertion with the same inputs and the same expected values.
- **Never weaken a test to make it pass.** Do not remove assertions, loosen expected values, or assert only that something does not crash. Do not change the implementation so that it special-cases a test. If a test fails, fix the implementation.
- Port the implementation from upstream, line by line in behavior, including odd cases. Do not write only what the tests touch: port the whole module, because real users call the rest.
- A check of a JavaScript-only fact needs the closest real Rust check of the same behavior. For example, "toJSON does not throw on a string in a long field" becomes the same input given as a `Json` string. Add a `// adapted: <why>` comment.
- When a test has no meaningful Rust version, do not fake it. Leave it out and add one line to `tests-data/not-ported.md` with the test name and the reason. An honest gap is much better than a fake pass.
- Write no tests other than the ledger entries.

## Style

- Match the code around you: short doc comments, same names as upstream in snake_case.
- Hot paths must not use `format!` or needless clones.
- Keep behavior of error messages and status codes the same as upstream, since tests and users read them.
- Do not run `cargo fmt` over files you do not own.

## Reporting back

Report: what you ported, the suites and how many pass, every test left out with the reason, each place where you could not match upstream, and anything another agent must know. Report failures plainly.
