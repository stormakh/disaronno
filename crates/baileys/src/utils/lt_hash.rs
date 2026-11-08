//! LT hash, same results as LTHashAntiTampering in whatsapp-rust-bridge.
use crate::crypto::hkdf;
const INFO: &[u8; 24] = b"WhatsApp Patch Integrity";

fn apply(state: &mut [u8], e: &[u8], add: bool) {
    for (s, x) in state.chunks_exact_mut(2).zip(e.chunks_exact(2)) {
        let a = u16::from_le_bytes([s[0], s[1]]);
        let b = u16::from_le_bytes([x[0], x[1]]);
        let r = if add { a.wrapping_add(b) } else { a.wrapping_sub(b) };
        s.copy_from_slice(&r.to_le_bytes());
    }
}
fn mix(state: &mut [u8], item: &[u8], add: bool) {
    apply(state, &hkdf(item, 128, None, INFO), add);
}
/// Hashes groups of eight items at once when the CPU can. Items that remain go through `mix`.
#[cfg(all(feature = "native", target_arch = "x86_64"))]
fn mix_all(state: &mut [u8], items: &[&[u8]], add: bool) {
    let mut groups = items.chunks_exact(8);
    for g in &mut groups {
        let refs: Option<Vec<&[u8; 32]>> = g.iter().map(|i| (*i).try_into().ok()).collect();
        match refs.and_then(|r| crate::crypto::hkdf_x8::hkdf_128_x8(&r.try_into().ok()?, INFO)) {
            Some(out) => out.iter().for_each(|e| apply(state, e, add)),
            None => g.iter().for_each(|i| mix(state, i, add)),
        }
    }
    groups.remainder().iter().for_each(|i| mix(state, i, add));
}
#[cfg(not(all(feature = "native", target_arch = "x86_64")))]
fn mix_all(state: &mut [u8], items: &[&[u8]], add: bool) {
    items.iter().for_each(|i| mix(state, i, add));
}
/// Subtracts every `sub` item, then adds every `add` item. Same argument order as the bridge.
pub fn subtract_then_add(base: &[u8], sub: &[&[u8]], add: &[&[u8]]) -> Vec<u8> {
    let mut s = base.to_vec();
    mix_all(&mut s, sub, false);
    mix_all(&mut s, add, true);
    s
}
