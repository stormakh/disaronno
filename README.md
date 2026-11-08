# disaronno

**Baileys, the WhatsApp Web library, ported to Rust.**

Why the name: [Baileys](https://github.com/WhiskeySockets/Baileys) shares its name with an Irish whiskey cream liqueur. Disaronno is an amaretto, and it is my favourite. So my own version, in Rust, is called disaronno.

## Numbers

All measured on one machine (Intel i7-8700) against the real Baileys build. The full report with method and caveats is [`bench/report.html`](bench/report.html).

| | Baileys (Node) | disaronno (Rust) | |
|---|---|---|---|
| Upstream tests | — | 407 of 407 pass | |
| Receive a message, end to end | 3,190 /s | 137,706 /s | 43X faster |
| XEdDSA signature | 105.5 /s | 33,507 /s | 318X faster |
| Typical speedup, 13 workloads | | | 15X (geometric mean) |
| Process start and library load | 192.7 ms | 1.6 ms | |
| Memory after 4 hours on a real account | 156.7 MB | 8.9 MB | 17.6X less (private memory: 13.6X less) |
| CPU over those 4 hours | 9.79 s | 1.46 s | 6.7X less |

The 4-hour runs used one personal account with a full history sync of about 201,000 messages. Rust with the memory fixes ran a day after Baileys, so the live traffic differed. The results files hold counts only: no message text, names or numbers.

## Status

- Ported: the socket, Noise, Signal, binary nodes, protobuf, app-state sync, history sync, media.
- Not ported: proxy agents and `uploadWithFetch`. Image and audio work uses ffmpeg in place of sharp, jimp and music-metadata.
- Different from upstream: work that Baileys starts at the same time runs in order on two queues. Protobuf and binary node decode reject input nested more than 64 levels.
- One real account linked, synced, received live messages and logged out. Sending real messages and media through a live socket is not tested yet.

## Build

```sh
cargo build --release
cargo test -p baileys
```

The test ledger and the bench compare against upstream sources that are not in this repo. To use them, clone them next to the code:

```sh
git clone https://github.com/WhiskeySockets/Baileys upstream && git -C upstream checkout 81345be
git clone https://github.com/t3dotgg/lust-lang && git -C lust-lang checkout 3173c6c0
node scripts/score.mjs        # 407/407
```

`PORTING.md` has the porting rules: the code in `crates/baileys/src` also compiles with `lust`.

## License

MIT. See [`LICENSE`](LICENSE), which also carries the Baileys license notice.
