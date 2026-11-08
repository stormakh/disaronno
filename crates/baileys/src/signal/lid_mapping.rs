//! PN to LID mappings, same behavior as Signal/lid-mapping.ts.
use crate::auth::{KeyKind, KeyValue, LidMapping, SignalKeyStore};
use crate::error::Result;
use crate::utils::time::now_ms;
use crate::wabinary::*;
use rustc_hash::FxHashMap;
use std::collections::BTreeSet;
use std::sync::{Arc, Mutex};
use std::sync::atomic::{AtomicUsize, Ordering};

const TTL_MS: i64 = 3 * 24 * 60 * 60 * 1000;
pub type PnToLidFn = Arc<dyn Fn(&[String]) -> Result<Option<Vec<LidMapping>>> + Send + Sync>;

const PURGE_MIN: usize = 1024;
pub struct LidMappingStore {
    cache: Mutex<FxHashMap<String, (String, i64)>>,
    purge_at: AtomicUsize,
    keys: Arc<dyn SignalKeyStore>,
    pn_to_lid: Option<PnToLidFn>,
}
fn dedupe(v: &[String]) -> Vec<String> {
    let mut seen = BTreeSet::new();
    v.iter().filter(|x| seen.insert((*x).clone())).cloned().collect()
}
/// Insertion-ordered result map, as `Object.values(successfulPairs)` reads.
#[derive(Default)]
struct Pairs(Vec<(String, LidMapping)>);
impl Pairs {
    fn put(&mut self, k: String, v: LidMapping) {
        match self.0.iter_mut().find(|(n, _)| *n == k) {
            Some(e) => e.1 = v,
            None => self.0.push((k, v)),
        }
    }
    fn done(self) -> Option<Vec<LidMapping>> {
        if self.0.is_empty() { None } else { Some(self.0.into_iter().map(|(_, v)| v).collect()) }
    }
}
impl LidMappingStore {
    pub fn new(keys: Arc<dyn SignalKeyStore>, pn_to_lid: Option<PnToLidFn>) -> LidMappingStore {
        LidMappingStore { cache: Mutex::new(FxHashMap::default()), purge_at: AtomicUsize::new(PURGE_MIN), keys, pn_to_lid }
    }
    fn cache_get(&self, k: &str) -> Option<String> {
        let mut c = self.cache.lock().unwrap();
        let now = now_ms();
        match c.get_mut(k) {
            Some(e) if e.1 > now => {
                e.1 = now + TTL_MS;
                Some(e.0.clone())
            }
            Some(_) => {
                c.remove(k);
                None
            }
            None => None,
        }
    }
    fn cache_pair(&self, pn_user: &str, lid_user: &str) {
        let now = now_ms();
        let exp = now + TTL_MS;
        let mut c = self.cache.lock().unwrap();
        // same job as `ttlAutopurge`, without a timer: the map doubles before a purge runs
        if c.len() >= self.purge_at.load(Ordering::Relaxed) {
            let mut expired = Vec::new();
            for (k, e) in c.iter() {
                if e.1 <= now {
                    expired.push(k.clone());
                }
            }
            for k in &expired {
                c.remove(k);
            }
            self.purge_at.store((c.len() * 2).max(PURGE_MIN), Ordering::Relaxed);
        }
        c.insert(format!("pn:{pn_user}"), (lid_user.to_string(), exp));
        c.insert(format!("lid:{lid_user}"), (pn_user.to_string(), exp));
    }
    pub fn store_lid_pn_mappings(&self, pairs: &[LidMapping]) -> Result<()> {
        let mut valid: Vec<(String, String)> = Vec::new();
        for p in pairs {
            if !((is_lid_user(&p.lid) && is_pn_user(&p.pn)) || (is_pn_user(&p.lid) && is_lid_user(&p.pn))) {
                continue;
            }
            let (Some(l), Some(n)) = (jid_decode(&p.lid), jid_decode(&p.pn)) else { continue };
            valid.push((n.user.to_string(), l.user.to_string()));
        }
        if valid.is_empty() {
            return Ok(());
        }
        let mut existing: FxHashMap<String, String> = FxHashMap::default();
        let mut misses = Vec::new();
        for (pn, _) in &valid {
            match self.cache_get(&format!("pn:{pn}")) {
                Some(c) => {
                    existing.insert(pn.clone(), c);
                }
                None => misses.push(pn.clone()),
            }
        }
        if !misses.is_empty() {
            let misses = dedupe(&misses);
            let stored = self.keys.get(KeyKind::LidMapping, &misses)?;
            for pn in &misses {
                if let Some(KeyValue::LidMapping(l)) = stored.get(pn) {
                    existing.insert(pn.clone(), l.clone());
                    self.cache_pair(pn, l);
                }
            }
        }
        let mut pair_map: Vec<(String, String)> = Vec::new();
        for (pn, lid) in valid {
            if existing.get(&pn) == Some(&lid) {
                continue;
            }
            match pair_map.iter_mut().find(|(n, _)| *n == pn) {
                Some(e) => e.1 = lid,
                None => pair_map.push((pn, lid)),
            }
        }
        if pair_map.is_empty() {
            return Ok(());
        }
        let mut writes = Vec::with_capacity(pair_map.len() * 2);
        for (pn, lid) in &pair_map {
            writes.push((KeyKind::LidMapping, pn.clone(), Some(KeyValue::LidMapping(lid.clone()))));
            writes.push((KeyKind::LidMapping, format!("{lid}_reverse"), Some(KeyValue::LidMapping(pn.clone()))));
        }
        let mut w = Some(writes);
        self.keys.transaction(&mut || self.keys.set(w.take().unwrap_or_default()), "lid-mapping")?;
        for (pn, lid) in &pair_map {
            self.cache_pair(pn, lid);
        }
        Ok(())
    }
    pub fn get_lid_for_pn(&self, pn: &str) -> Result<Option<String>> {
        Ok(self.get_lids_for_pns(&[pn.to_string()])?.and_then(|v| v.into_iter().next()).map(|m| m.lid).filter(|l| !l.is_empty()))
    }
    pub fn get_lids_for_pns(&self, pns: &[String]) -> Result<Option<Vec<LidMapping>>> {
        if pns.is_empty() {
            return Ok(None);
        }
        let mut ok = Pairs::default();
        let resolved = |ok: &mut Pairs, pn: &str, d: &FullJid<'_>, lid_user: &str| {
            if lid_user.is_empty() {
                return;
            }
            let device = d.device.unwrap_or(0);
            let server = if d.server == "hosted" { "hosted.lid" } else { "lid" };
            let lid = if device != 0 { format!("{lid_user}:{device}@{server}") } else { format!("{lid_user}@{server}") };
            ok.put(pn.to_string(), LidMapping { lid, pn: pn.to_string() });
        };
        let mut pending: Vec<&String> = Vec::new();
        for pn in pns {
            if !is_pn_user(pn) && !is_hosted_pn_user(pn) {
                continue;
            }
            let Some(d) = jid_decode(pn) else { continue };
            if let Some(c) = self.cache_get(&format!("pn:{}", d.user)) {
                resolved(&mut ok, pn, &d, &c);
            } else {
                pending.push(pn);
            }
        }
        let mut usync: Vec<(String, Vec<u32>)> = Vec::new();
        if !pending.is_empty() {
            let users: Vec<String> = pending.iter().filter_map(|p| jid_decode(p).map(|d| d.user.to_string())).collect();
            let users = dedupe(&users);
            let stored = self.keys.get(KeyKind::LidMapping, &users)?;
            for u in &users {
                if let Some(KeyValue::LidMapping(l)) = stored.get(u) {
                    if !l.is_empty() {
                        self.cache_pair(u, l);
                    }
                }
            }
            for pn in pending {
                let Some(d) = jid_decode(pn) else { continue };
                if let Some(c) = self.cache_get(&format!("pn:{}", d.user)) {
                    resolved(&mut ok, pn, &d, &c);
                } else {
                    let device = d.device.unwrap_or(0);
                    let mut norm = jid_normalized_user(pn);
                    if is_hosted_pn_user(&norm) {
                        norm = format!("{}@s.whatsapp.net", d.user);
                    }
                    match usync.iter_mut().find(|(n, _)| *n == norm) {
                        Some(e) => e.1.push(device),
                        None => usync.push((norm, vec![device])),
                    }
                }
            }
        }
        if !usync.is_empty() {
            let names: Vec<String> = usync.iter().map(|(n, _)| n.clone()).collect();
            let result = match &self.pn_to_lid {
                Some(f) => f(&names)?,
                None => None,
            };
            if let Some(result) = result.filter(|r| !r.is_empty()) {
                self.store_lid_pn_mappings(&result)?;
                for pair in &result {
                    let Some(pn_user) = jid_decode(&pair.pn).map(|d| d.user.to_string()) else { continue };
                    let Some(lid_user) = jid_decode(&pair.lid).map(|d| d.user.to_string()) else { continue };
                    let Some((_, devices)) = usync.iter().find(|(n, _)| *n == pair.pn) else { continue };
                    for device in devices {
                        let dev = if *device != 0 { format!(":{device}") } else { String::new() };
                        let hosted = *device == 99;
                        let lid = format!("{lid_user}{dev}@{}", if hosted { "hosted.lid" } else { "lid" });
                        let pn = format!("{pn_user}{dev}@{}", if hosted { "hosted" } else { "s.whatsapp.net" });
                        ok.put(pn.clone(), LidMapping { lid, pn });
                    }
                }
            }
        }
        Ok(ok.done())
    }
    pub fn get_pn_for_lid(&self, lid: &str) -> Result<Option<String>> {
        Ok(self.get_pns_for_lids(&[lid.to_string()])?.and_then(|v| v.into_iter().next()).map(|m| m.pn).filter(|p| !p.is_empty()))
    }
    pub fn get_pns_for_lids(&self, lids: &[String]) -> Result<Option<Vec<LidMapping>>> {
        if lids.is_empty() {
            return Ok(None);
        }
        let mut ok = Pairs::default();
        let resolved = |ok: &mut Pairs, lid: &str, d: &FullJid<'_>, pn_user: &str| {
            if pn_user.is_empty() {
                return;
            }
            let device = d.device.unwrap_or(0);
            let server = if d.domain_type == domains::HOSTED_LID { "hosted" } else { "s.whatsapp.net" };
            ok.put(lid.to_string(), LidMapping { lid: lid.to_string(), pn: format!("{pn_user}:{device}@{server}") });
        };
        let mut pending: Vec<&String> = Vec::new();
        for lid in lids {
            if !is_lid_user(lid) {
                continue;
            }
            let Some(d) = jid_decode(lid) else { continue };
            if let Some(c) = self.cache_get(&format!("lid:{}", d.user)) {
                resolved(&mut ok, lid, &d, &c);
            } else {
                pending.push(lid);
            }
        }
        if !pending.is_empty() {
            let keys: Vec<String> = pending.iter().filter_map(|l| jid_decode(l).map(|d| format!("{}_reverse", d.user))).collect();
            let keys = dedupe(&keys);
            let stored = self.keys.get(KeyKind::LidMapping, &keys)?;
            for lid in pending {
                let Some(d) = jid_decode(lid) else { continue };
                let mut pn = self.cache_get(&format!("lid:{}", d.user));
                if pn.is_none() {
                    if let Some(KeyValue::LidMapping(p)) = stored.get(&format!("{}_reverse", d.user)) {
                        if !p.is_empty() {
                            self.cache_pair(p, d.user);
                            pn = Some(p.clone());
                        }
                    }
                }
                if let Some(p) = pn {
                    resolved(&mut ok, lid, &d, &p);
                }
            }
        }
        Ok(ok.done())
    }
    pub fn close(&self) {
        self.cache.lock().unwrap().clear();
    }
}
