#!/bin/sh
# Regenerates crates/baileys/hot-functions.txt: the functions that run, smallest flows first, so they sit together.
# Run from the repo root, after a change that moves many functions. A stale list costs memory only.
set -e
W=target/hot-functions
mkdir -p "$W"
rm -f "$W"/out-*.txt
cc -O2 -w -o "$W/fn-coverage" scripts/fn-coverage.c
cargo build --release -p baileys --bin baileys-bench --example e2e_driver
cp target/release/baileys-bench "$W/bench"
cp target/release/examples/e2e_driver "$W/driver"
for b in bench driver; do nm "$W/$b" | awk 'NF==3 && $2 ~ /[tTwWi]/' > "$W/$b.nm"; done
for mode in idle memory-compact memory; do
	COV_OUT="$W/out-$mode.txt" "$W/fn-coverage" "$W/bench.nm" "$W/bench" "$mode" > /dev/null
done
cat > "$W/driver.sh" <<WRAP
#!/bin/sh
COV_OUT="$PWD/$W/out-driver.txt" exec "$PWD/$W/fn-coverage" "$PWD/$W/driver.nm" "$PWD/$W/driver" "\$@"
WRAP
chmod +x "$W/driver.sh"
E2E_DRIVER="$PWD/$W/driver.sh" node scripts/e2e.mjs rust-rust > /dev/null
cat "$W/out-idle.txt" "$W/out-memory-compact.txt" "$W/out-memory.txt" "$W/out-driver.txt" | awk '!seen[$0]++' > crates/baileys/hot-functions.txt
wc -l crates/baileys/hot-functions.txt
