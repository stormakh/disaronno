//! Port of Signal/lid-mapping.test.ts.
use baileys::auth::{KeyKind, KeyMap, KeyValue, KeyWrite, LidMapping, SignalKeyStore};
use baileys::error::Result;
use baileys::signal::lid_mapping::{LidMappingStore, PnToLidFn};
use std::sync::{Arc, Mutex};

const HOSTED_DEVICE_ID: u32 = 99;

/// `mockKeys.get.mockResolvedValue(..)`: every `get` returns this same value.
struct MockKeys {
    get_result: Mutex<KeyMap>,
}
impl SignalKeyStore for MockKeys {
    fn get(&self, _kind: KeyKind, _ids: &[String]) -> Result<KeyMap> {
        Ok(self.get_result.lock().unwrap().clone())
    }
    fn set(&self, _data: Vec<KeyWrite>) -> Result<()> {
        Ok(())
    }
}
fn store(values: &[(&str, &str)]) -> LidMappingStore {
    let mut get_result = KeyMap::default();
    for (k, v) in values {
        get_result.insert(k.to_string(), KeyValue::LidMapping(v.to_string()));
    }
    let pn_to_lid: PnToLidFn = Arc::new(|_: &[String]| -> Result<Option<Vec<LidMapping>>> { Ok(None) });
    LidMappingStore::new(Arc::new(MockKeys { get_result: Mutex::new(get_result) }), Some(pn_to_lid))
}
#[test]
fn t_lidmappingstore_getpnforlid_should_correctly_map_a_standard_lid_with_a_hosted_device_id_back_to_a_standard_pn_with_a_hosted_device() {
    let lid_with_hosted_device = format!("12345:{HOSTED_DEVICE_ID}@lid");
    let pn_user = "54321";
    let s = store(&[("12345_reverse", pn_user)]);
    let result = s.get_pn_for_lid(&lid_with_hosted_device).unwrap();
    assert_eq!(result, Some(format!("{pn_user}:{HOSTED_DEVICE_ID}@s.whatsapp.net")));
}
#[test]
fn t_lidmappingstore_getpnforlid_should_return_null_if_no_reverse_mapping_is_found() {
    let lid = "nonexistent@lid";
    // Simulate not found in DB
    let s = store(&[]);
    assert_eq!(s.get_pn_for_lid(lid).unwrap(), None);
}
