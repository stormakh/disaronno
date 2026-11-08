//! Same as WAM/encode.ts.
use super::constants::*;
use super::{BinaryInfo, Value, find_event, find_global};
use crate::error::{Boom, Result};

/// `Buffer.alloc(0)` when there is nothing is not possible upstream: the header always exists.
pub fn encode_wam(binary_info: &mut BinaryInfo) -> Result<Vec<u8>> {
    binary_info.buffer = Vec::new();
    encode_wam_header(binary_info);
    encode_events(binary_info)?;
    Ok(binary_info.buffer.concat())
}
fn encode_wam_header(binary_info: &mut BinaryInfo) {
    let mut header = Vec::with_capacity(8);
    header.extend_from_slice(b"WAM");
    header.push(binary_info.protocol_version);
    header.push(1); // random flag
    header.extend_from_slice(&binary_info.sequence.to_be_bytes());
    header.push(0); // regular channel
    binary_info.buffer.push(header);
}
fn encode_global_attributes(buffer: &mut Vec<Vec<u8>>, globals: &[(String, Value)]) -> Result<()> {
    for (key, value) in globals {
        let id = find_global(key).ok_or_else(|| Boom::type_error("Cannot read properties of undefined (reading 'id')"))?.id;
        buffer.push(serialize_data(id, value, FLAG_GLOBAL)?);
    }
    Ok(())
}
fn encode_events(binary_info: &mut BinaryInfo) -> Result<()> {
    let BinaryInfo { events, buffer, .. } = binary_info;
    for input in events.iter() {
        encode_global_attributes(buffer, &input.globals)?;
        let event = find_event(&input.name).ok_or_else(|| Boom::type_error("Cannot read properties of undefined (reading 'id')"))?;
        let extended = input.props.iter().any(|(_, v)| *v != Value::Null);
        let event_flag = if extended { FLAG_EVENT } else { FLAG_EVENT | FLAG_EXTENDED };
        buffer.push(serialize_data(event.id, &Value::Number(-(event.weight as f64)), event_flag)?);
        for (i, (key, value)) in input.props.iter().enumerate() {
            let id = event.props.iter().find(|p| p.name == key).map(|p| p.id).ok_or_else(|| Boom::new("missing"))?;
            let extended = i + 1 < input.props.len();
            let field_flag = if extended { FLAG_EVENT } else { FLAG_FIELD | FLAG_EXTENDED };
            buffer.push(serialize_data(id, value, field_flag)?);
        }
    }
    Ok(())
}
fn serialize_data(key: u32, value: &Value, flag: u8) -> Result<Vec<u8>> {
    let mut b = Vec::with_capacity(16);
    let num = |n: f64| Value::Number(n);
    let bool_value;
    let value = match value {
        Value::Bool(v) => {
            bool_value = num(if *v { 1.0 } else { 0.0 });
            &bool_value
        }
        v => v,
    };
    match value {
        Value::Null if flag == FLAG_GLOBAL => serialize_header(&mut b, key, flag),
        Value::Number(n) if n.is_finite() && n.fract() == 0.0 => {
            let v = *n;
            if v == 0.0 || v == 1.0 {
                serialize_header(&mut b, key, flag | ((v as u8 + 1) << 4));
            } else if v >= -128.0 && v < 128.0 {
                serialize_header(&mut b, key, flag | (3 << 4));
                b.push(v as i8 as u8);
            } else if v >= -32768.0 && v < 32768.0 {
                serialize_header(&mut b, key, flag | (4 << 4));
                b.extend_from_slice(&(v as i16).to_le_bytes());
            } else if v >= -2147483648.0 && v < 2147483648.0 {
                serialize_header(&mut b, key, flag | (5 << 4));
                b.extend_from_slice(&(v as i32).to_le_bytes());
            } else {
                serialize_header(&mut b, key, flag | (7 << 4));
                b.extend_from_slice(&v.to_bits().to_le_bytes());
            }
        }
        Value::Number(n) => {
            serialize_header(&mut b, key, flag | (7 << 4));
            b.extend_from_slice(&n.to_bits().to_le_bytes());
        }
        Value::Str(s) => {
            let len = s.len();
            if len < 256 {
                serialize_header(&mut b, key, flag | (8 << 4));
                b.push(len as u8);
            } else if len < 65536 {
                serialize_header(&mut b, key, flag | (9 << 4));
                b.extend_from_slice(&(len as u16).to_le_bytes());
            } else {
                serialize_header(&mut b, key, flag | (10 << 4));
                b.extend_from_slice(&(len as u32).to_le_bytes());
            }
            b.extend_from_slice(s.as_bytes());
        }
        _ => return Err(Boom::new("missing")),
    }
    Ok(b)
}
fn serialize_header(b: &mut Vec<u8>, key: u32, flag: u8) {
    if key < 256 {
        b.push(flag);
        b.push(key as u8);
    } else {
        b.push(flag | FLAG_BYTE);
        b.extend_from_slice(&(key as u16).to_le_bytes());
    }
}
