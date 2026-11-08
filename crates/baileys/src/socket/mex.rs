//! Same as Socket/mex.ts.
use super::socket::{SocketInner, content_string};
use crate::error::{Boom, Result};
use crate::wabinary::{Attrs, BinaryNode, S_WHATSAPP_NET, get_binary_node_child};
use waproto::pb::Json;

fn w_mex_query(sock: &SocketInner, variables: Json, query_id: &str) -> Result<Option<BinaryNode>> {
    let mut attrs = Attrs::new();
    attrs.set("id", sock.generate_message_tag());
    attrs.set("type", "get");
    attrs.set("to", S_WHATSAPP_NET);
    attrs.set("xmlns", "w:mex");
    let body = Json::Obj(vec![("variables".to_string(), variables)]).stringify();
    sock.query(BinaryNode::with_nodes("iq", attrs, vec![BinaryNode::with_bytes("query", Attrs::from([("query_id", query_id)]), body.as_bytes())]), None)
}
pub fn execute_wmex_query(sock: &SocketInner, variables: Json, query_id: &str, data_path: &str) -> Result<Json> {
    let result = w_mex_query(sock, variables, query_id)?;
    let child = get_binary_node_child(result.as_ref(), "result");
    if let Some(text) = content_string(child) {
        let data = Json::parse(&text)?;
        if let Some(errors) = data.get("errors").and_then(Json::as_arr).filter(|e| !e.is_empty()) {
            let messages: Vec<&str> = errors.iter().map(|e| e.get("message").and_then(Json::as_str).filter(|m| !m.is_empty()).unwrap_or("Unknown error")).collect();
            let first = &errors[0];
            let code = first.get("extensions").and_then(|x| x.get("error_code")).and_then(Json::as_f64).filter(|c| *c != 0.0).unwrap_or(400.0) as u16;
            let mut e = Boom::with_data(format!("GraphQL server error: {}", messages.join(", ")), first.clone());
            e.status_code = Some(code);
            return Err(e);
        }
        let inner = data.get("data");
        let response = if data_path.is_empty() { inner } else { inner.and_then(|d| d.get(data_path)) };
        if let Some(r) = response {
            return Ok(r.clone());
        }
    }
    let action = data_path.strip_prefix("xwa2_").unwrap_or(data_path).replace('_', " ");
    Err(Boom::status(format!("Failed to {action}, unexpected response structure."), 400))
}
