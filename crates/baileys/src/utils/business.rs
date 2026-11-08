//! Same behavior as Utils/business.ts.
use crate::crypto::Sha256Stream;
use crate::defaults::MediaType;
use crate::error::{Boom, Result};
use crate::types::*;
use crate::utils::generics::generate_message_id_v2;
use crate::utils::messages_media::{GetStreamResult, get_stream, get_url_from_direct_path};
use crate::utils::tc_token_utils::js_to_number;
use crate::wabinary::{Attrs, BinaryNode, get_binary_node_child, get_binary_node_child_string, get_binary_node_children};
use std::io::Write;
use waproto::pb::{base64_encode, js_number};

fn child_str(n: Option<&BinaryNode>, tag: &str) -> String {
    get_binary_node_child_string(n, tag).unwrap_or_default()
}
fn child_num(n: Option<&BinaryNode>, tag: &str) -> f64 {
    get_binary_node_child_string(n, tag).as_deref().map_or(f64::NAN, js_to_number)
}
#[derive(Clone, Debug, PartialEq, Default)]
pub struct ParsedCatalog {
    pub products: Vec<Product>,
    pub next_page_cursor: Option<String>,
}
pub fn parse_catalog_node(node: &BinaryNode) -> ParsedCatalog {
    let catalog_node = get_binary_node_child(Some(node), "product_catalog");
    let products = get_binary_node_children(catalog_node, "product").into_iter().map(parse_product_node).collect();
    let paging = get_binary_node_child(catalog_node, "paging");
    ParsedCatalog { products, next_page_cursor: paging.and_then(|p| get_binary_node_child_string(Some(p), "after")) }
}
pub fn parse_collections_node(node: &BinaryNode) -> Vec<CatalogCollection> {
    let collections_node = get_binary_node_child(Some(node), "collections");
    get_binary_node_children(collections_node, "collection")
        .into_iter()
        .map(|c| CatalogCollection {
            id: child_str(Some(c), "id"),
            name: child_str(Some(c), "name"),
            products: get_binary_node_children(Some(c), "product").into_iter().map(parse_product_node).collect(),
            status: parse_status_info(c),
        })
        .collect()
}
pub fn parse_order_details_node(node: &BinaryNode) -> OrderDetails {
    let order_node = get_binary_node_child(Some(node), "order");
    let products = get_binary_node_children(order_node, "product")
        .into_iter()
        .map(|p| {
            let image_node = get_binary_node_child(Some(p), "image");
            OrderProduct {
                id: child_str(Some(p), "id"),
                name: child_str(Some(p), "name"),
                image_url: child_str(image_node, "url"),
                price: child_num(Some(p), "price"),
                currency: child_str(Some(p), "currency"),
                quantity: child_num(Some(p), "quantity") as u32,
            }
        })
        .collect();
    let price_node = get_binary_node_child(order_node, "price");
    OrderDetails { price: OrderPrice { total: child_num(price_node, "total"), currency: child_str(price_node, "currency") }, products }
}
/// `ProductCreate | ProductUpdate`. Only a create has `originCountryCode`.
#[derive(Clone, Copy)]
pub enum ProductInput<'a> {
    Create(&'a ProductCreate),
    Update(&'a ProductUpdate),
}
fn text_node(tag: &str, text: &str) -> BinaryNode {
    BinaryNode::with_bytes(tag, Attrs::new(), text.as_bytes())
}
pub fn to_product_node(product_id: Option<&str>, product: ProductInput<'_>) -> Result<BinaryNode> {
    let mut attrs = Attrs::new();
    let mut content: Vec<BinaryNode> = Vec::new();
    let (base, images) = match product {
        ProductInput::Create(p) => (&p.base, &p.images),
        ProductInput::Update(p) => (&p.base, &p.images),
    };
    if let Some(id) = product_id {
        content.push(text_node("id", id));
    }
    content.push(text_node("name", &base.name));
    content.push(text_node("description", &base.description));
    if let Some(r) = &base.retailer_id {
        content.push(text_node("retailer_id", r));
    }
    if !images.is_empty() {
        let mut nodes = Vec::with_capacity(images.len());
        for img in images {
            let WAMediaUpload::Url(url) = img else {
                return Err(Boom::status("Expected img for product to already be uploaded", 400));
            };
            nodes.push(BinaryNode::with_nodes("image", Attrs::new(), vec![text_node("url", url)]));
        }
        content.push(BinaryNode::with_nodes("media", Attrs::new(), nodes));
    }
    content.push(text_node("price", &js_number(base.price)));
    content.push(text_node("currency", &base.currency));
    if let ProductInput::Create(p) = product {
        match &p.origin_country_code {
            None => attrs.set("compliance_category", "COUNTRY_ORIGIN_EXEMPT"),
            Some(code) => content.push(BinaryNode::with_nodes("compliance_info", Attrs::new(), vec![text_node("country_code_origin", code)])),
        }
    }
    if let Some(h) = base.is_hidden {
        attrs.set("is_hidden", if h { "true" } else { "false" });
    }
    Ok(BinaryNode::with_nodes("product", attrs, content))
}
pub fn parse_product_node(product_node: &BinaryNode) -> Product {
    let media_node = get_binary_node_child(Some(product_node), "media");
    let status_info_node = get_binary_node_child(Some(product_node), "status_info");
    Product {
        base: ProductBase {
            name: child_str(Some(product_node), "name"),
            retailer_id: get_binary_node_child_string(Some(product_node), "retailer_id"),
            url: get_binary_node_child_string(Some(product_node), "url"),
            description: child_str(Some(product_node), "description"),
            price: child_num(Some(product_node), "price"),
            currency: child_str(Some(product_node), "currency"),
            is_hidden: Some(product_node.attr("is_hidden") == Some("true")),
        },
        id: child_str(Some(product_node), "id"),
        image_urls: parse_image_urls(media_node),
        review_status: vec![("whatsapp".to_string(), child_str(status_info_node, "status"))],
        availability: "in stock".to_string(),
    }
}
/// Uploads images not already uploaded to WA's servers
pub fn uploading_necessary_images_of_product(product: &ProductCreate, wa_upload_to_server: &WAMediaUploadFunction, timeout_ms: Option<u64>) -> Result<ProductCreate> {
    let mut p = product.clone();
    p.images = uploading_necessary_images(&product.images, wa_upload_to_server, timeout_ms)?.into_iter().map(WAMediaUpload::Url).collect();
    Ok(p)
}
/// `uploadingNecessaryImagesOfProduct` for a `ProductUpdate`.
pub fn uploading_necessary_images_of_product_update(product: &ProductUpdate, wa_upload_to_server: &WAMediaUploadFunction, timeout_ms: Option<u64>) -> Result<ProductUpdate> {
    let mut p = product.clone();
    p.images = uploading_necessary_images(&product.images, wa_upload_to_server, timeout_ms)?.into_iter().map(WAMediaUpload::Url).collect();
    Ok(p)
}
/// Uploads images not already uploaded to WA's servers. Returns the URL of each image.
pub fn uploading_necessary_images(images: &[WAMediaUpload], wa_upload_to_server: &WAMediaUploadFunction, timeout_ms: Option<u64>) -> Result<Vec<String>> {
    let timeout_ms = timeout_ms.unwrap_or(30_000);
    let mut results = Vec::with_capacity(images.len());
    for img in images {
        if let WAMediaUpload::Url(url) = img {
            if url.contains(".whatsapp.net") {
                results.push(url.clone());
                continue;
            }
        }
        let GetStreamResult { stream, .. } = get_stream(img, None)?;
        let mut hasher = Sha256Stream::new();
        let file_path = std::env::temp_dir().join(format!("img{}", generate_message_id_v2(None))).to_string_lossy().into_owned();
        let mut file = std::fs::File::create(&file_path).map_err(|e| Boom::new(e.to_string()))?;
        let mut buf = vec![0u8; 64 * 1024];
        loop {
            let n = stream.read(&mut buf)?;
            if n == 0 {
                break;
            }
            hasher.update(&buf[..n]);
            file.write_all(&buf[..n]).map_err(|e| Boom::new(e.to_string()))?;
        }
        drop(file);
        let sha = base64_encode(&hasher.finish());
        let result = wa_upload_to_server(&file_path, &MediaUploadOpts { media_type: MediaType::ProductCatalogImage, file_enc_sha256_b64: sha, timeout_ms: Some(timeout_ms) });
        let _ = std::fs::remove_file(&file_path);
        results.push(get_url_from_direct_path(&result?.direct_path, None));
    }
    Ok(results)
}
fn parse_image_urls(media_node: Option<&BinaryNode>) -> Vec<(String, String)> {
    let img_node = get_binary_node_child(media_node, "image");
    vec![("requested".to_string(), child_str(img_node, "request_image_url")), ("original".to_string(), child_str(img_node, "original_image_url"))]
}
fn parse_status_info(media_node: &BinaryNode) -> CatalogStatus {
    let node = get_binary_node_child(Some(media_node), "status_info");
    CatalogStatus { status: child_str(node, "status"), can_appeal: get_binary_node_child_string(node, "can_appeal").as_deref() == Some("true") }
}
