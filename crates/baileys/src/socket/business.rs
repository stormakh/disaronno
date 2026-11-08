//! Same as Socket/business.ts.
use super::socket::SocketInner;
use crate::defaults::MediaType;
use crate::error::{Boom, Result};
use crate::types::*;
use crate::utils::business::*;
use crate::utils::messages_media::get_raw_media_upload_data;
use crate::wabinary::*;
use waproto::pb::base64_encode;

fn biz_iq(content: Vec<BinaryNode>) -> BinaryNode {
    BinaryNode::with_nodes("iq", Attrs::from([("to", S_WHATSAPP_NET), ("type", "set"), ("xmlns", "w:biz")]), vec![BinaryNode::with_nodes("business_profile", Attrs::from([("v", "3"), ("mutation_type", "delta")]), content)])
}
fn catalog_iq(r#type: &str, content: BinaryNode) -> BinaryNode {
    BinaryNode::with_nodes("iq", Attrs::from([("to", S_WHATSAPP_NET), ("type", r#type), ("xmlns", "w:biz:catalog")]), vec![content])
}
fn bytes(tag: &str, text: &str) -> BinaryNode {
    BinaryNode::with_bytes(tag, Attrs::new(), text.as_bytes())
}
impl SocketInner {
    fn normalized_jid_or_me(&self, jid: Option<&str>) -> String {
        let me = self.me_id();
        jid_normalized_user(jid.filter(|j| !j.is_empty()).or(me.as_deref()).unwrap_or(""))
    }
    pub fn update_bussines_profile(&self, args: &UpdateBussinesProfileProps) -> Result<Option<BinaryNode>> {
        let mut node = Vec::new();
        for (key, value) in [("address", &args.address), ("email", &args.email), ("description", &args.description)] {
            if let Some(v) = value {
                node.push(BinaryNode::with_text(key, Attrs::new(), v.as_str()));
            }
        }
        if let Some(websites) = &args.websites {
            node.extend(websites.iter().map(|w| BinaryNode::with_text("website", Attrs::new(), w.as_str())));
        }
        if let Some(hours) = &args.hours {
            let days = hours
                .days
                .iter()
                .map(|day| match day {
                    HoursDay::SpecificHours { day, open_time_in_minutes, close_time_in_minutes } => {
                        let mut attrs = Attrs::from([("day_of_week", day.as_str()), ("mode", "specific_hours")]);
                        attrs.set("open_time", open_time_in_minutes.as_str());
                        attrs.set("close_time", close_time_in_minutes.as_str());
                        BinaryNode::tag("business_hours_config", attrs)
                    }
                    HoursDay::Open24h { day } => BinaryNode::tag("business_hours_config", Attrs::from([("day_of_week", day.as_str()), ("mode", "open_24h")])),
                    HoursDay::AppointmentOnly { day } => BinaryNode::tag("business_hours_config", Attrs::from([("day_of_week", day.as_str()), ("mode", "appointment_only")])),
                })
                .collect();
            node.push(BinaryNode::with_nodes("business_hours", Attrs::from([("timezone", hours.timezone.as_str())]), days));
        }
        self.query(biz_iq(node), None)
    }
    pub fn update_cover_photo(&self, photo: &WAMediaUpload) -> Result<u64> {
        let raw = get_raw_media_upload_data(photo, MediaType::BizCoverPhoto, Some(self.logger.as_ref()))?;
        let opts = MediaUploadOpts { file_enc_sha256_b64: base64_encode(&raw.file_sha256), media_type: MediaType::BizCoverPhoto, timeout_ms: None };
        let upload = (self.send.wa_upload_to_server)(&raw.file_path, &opts)?;
        let mut attrs = Attrs::new();
        attrs.set("id", upload.fbid.map_or("undefined".to_string(), |f| f.to_string()));
        attrs.set("op", "update");
        attrs.set("token", upload.meta_hmac.clone().unwrap_or_default());
        attrs.set("ts", upload.ts.map_or("undefined".to_string(), |t| t.to_string()));
        self.query(biz_iq(vec![BinaryNode::tag("cover_photo", attrs)]), None)?;
        upload.fbid.ok_or_else(|| Boom::new("cover photo upload gave no fbid"))
    }
    pub fn remove_cover_photo(&self, id: &str) -> Result<Option<BinaryNode>> {
        self.query(biz_iq(vec![BinaryNode::tag("cover_photo", Attrs::from([("op", "delete"), ("id", id)]))]), None)
    }
    pub fn get_catalog(&self, options: &GetCatalogOptions) -> Result<ParsedCatalog> {
        let jid = self.normalized_jid_or_me(options.jid.as_deref());
        let mut params = vec![bytes("limit", &options.limit.filter(|l| *l != 0).unwrap_or(10).to_string()), bytes("width", "100"), bytes("height", "100")];
        if let Some(c) = options.cursor.as_deref().filter(|c| !c.is_empty()) {
            params.push(BinaryNode::with_text("after", Attrs::new(), c));
        }
        let result = self.query(catalog_iq("get", BinaryNode::with_nodes("product_catalog", Attrs::from([("jid", jid.as_str()), ("allow_shop_source", "true")]), params)), None)?;
        Ok(parse_catalog_node(result.as_ref().ok_or_else(missing)?))
    }
    pub fn get_collections(&self, jid: Option<&str>, limit: Option<u32>) -> Result<Vec<CatalogCollection>> {
        let jid = self.normalized_jid_or_me(jid);
        let limit = limit.unwrap_or(51).to_string();
        let content = vec![bytes("collection_limit", &limit), bytes("item_limit", &limit), bytes("width", "100"), bytes("height", "100")];
        let result = self.query(BinaryNode::with_nodes("iq", Attrs::from([("to", S_WHATSAPP_NET), ("type", "get"), ("xmlns", "w:biz:catalog"), ("smax_id", "35")]), vec![BinaryNode::with_nodes("collections", Attrs::from([("biz_jid", jid.as_str())]), content)]), None)?;
        Ok(parse_collections_node(result.as_ref().ok_or_else(missing)?))
    }
    pub fn get_order_details(&self, order_id: &str, token_base64: &str) -> Result<OrderDetails> {
        let dimensions = BinaryNode::with_nodes("image_dimensions", Attrs::new(), vec![bytes("width", "100"), bytes("height", "100")]);
        let order = BinaryNode::with_nodes("order", Attrs::from([("op", "get"), ("id", order_id)]), vec![dimensions, bytes("token", token_base64)]);
        let result = self.query(BinaryNode::with_nodes("iq", Attrs::from([("to", S_WHATSAPP_NET), ("type", "get"), ("xmlns", "fb:thrift_iq"), ("smax_id", "5")]), vec![order]), None)?;
        Ok(parse_order_details_node(result.as_ref().ok_or_else(missing)?))
    }
    pub fn product_update(&self, product_id: &str, update: &ProductUpdate) -> Result<Product> {
        let update = uploading_necessary_images_of_product_update(update, &self.send.wa_upload_to_server, None)?;
        let edit_node = to_product_node(Some(product_id), ProductInput::Update(&update))?;
        let content = vec![edit_node, BinaryNode::with_text("width", Attrs::new(), "100"), BinaryNode::with_text("height", Attrs::new(), "100")];
        let result = self.query(catalog_iq("set", BinaryNode::with_nodes("product_catalog_edit", Attrs::from([("v", "1")]), content)), None)?;
        let edit = get_binary_node_child(result.as_ref(), "product_catalog_edit");
        Ok(parse_product_node(get_binary_node_child(edit, "product").ok_or_else(missing)?))
    }
    pub fn product_create(&self, create: &ProductCreate) -> Result<Product> {
        // ensure isHidden is defined
        let mut create = create.clone();
        create.base.is_hidden = Some(create.base.is_hidden.unwrap_or(false));
        let create = uploading_necessary_images_of_product(&create, &self.send.wa_upload_to_server, None)?;
        let create_node = to_product_node(None, ProductInput::Create(&create))?;
        let content = vec![create_node, BinaryNode::with_text("width", Attrs::new(), "100"), BinaryNode::with_text("height", Attrs::new(), "100")];
        let result = self.query(catalog_iq("set", BinaryNode::with_nodes("product_catalog_add", Attrs::from([("v", "1")]), content)), None)?;
        let add = get_binary_node_child(result.as_ref(), "product_catalog_add");
        Ok(parse_product_node(get_binary_node_child(add, "product").ok_or_else(missing)?))
    }
    /// The value is the `deleted` count.
    pub fn product_delete(&self, product_ids: &[String]) -> Result<u32> {
        let products = product_ids.iter().map(|id| BinaryNode::with_nodes("product", Attrs::new(), vec![bytes("id", id)])).collect();
        let result = self.query(catalog_iq("set", BinaryNode::with_nodes("product_catalog_delete", Attrs::from([("v", "1")]), products)), None)?;
        let node = get_binary_node_child(result.as_ref(), "product_catalog_delete");
        Ok(node.and_then(|n| n.attr("deleted_count")).filter(|c| !c.is_empty()).and_then(|c| c.parse().ok()).unwrap_or(0))
    }
}
fn missing() -> Boom {
    Boom::type_error("Cannot read properties of undefined (reading 'attrs')")
}
