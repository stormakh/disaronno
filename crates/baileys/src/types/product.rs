//! Same types as Types/Product.ts.
use super::message::WAMediaUpload;
use waproto::pb::Json;

#[derive(Clone, Debug, PartialEq, Default)]
pub struct CatalogPaging {
    pub before: String,
    pub after: String,
}
#[derive(Clone, Debug, PartialEq, Default)]
pub struct CatalogResult {
    pub paging: CatalogPaging,
    pub data: Vec<Json>,
}
#[derive(Clone, Debug, PartialEq, Default)]
pub struct CatalogStatus {
    pub status: String,
    pub can_appeal: bool,
}
#[derive(Clone, Debug, PartialEq, Default)]
pub struct CatalogCollection {
    pub id: String,
    pub name: String,
    pub products: Vec<Product>,
    pub status: CatalogStatus,
}
#[derive(Clone, Debug, PartialEq, Default)]
pub struct ProductBase {
    pub name: String,
    pub retailer_id: Option<String>,
    pub url: Option<String>,
    pub description: String,
    pub price: f64,
    pub currency: String,
    pub is_hidden: Option<bool>,
}
#[derive(Clone, Default)]
pub struct ProductCreate {
    pub base: ProductBase,
    /// ISO country code for product origin. Set to `None` for no country
    pub origin_country_code: Option<String>,
    /// images of the product
    pub images: Vec<WAMediaUpload>,
}
#[derive(Clone, Default)]
pub struct ProductUpdate {
    pub base: ProductBase,
    pub images: Vec<WAMediaUpload>,
}
#[derive(Clone, Debug, PartialEq, Default)]
pub struct Product {
    pub base: ProductBase,
    pub id: String,
    pub image_urls: Vec<(String, String)>,
    pub review_status: Vec<(String, String)>,
    /// The only value upstream has is `in stock`.
    pub availability: String,
}
impl std::ops::Deref for Product {
    type Target = ProductBase;
    fn deref(&self) -> &ProductBase {
        &self.base
    }
}
#[derive(Clone, Debug, PartialEq, Default)]
pub struct OrderPrice {
    pub currency: String,
    pub total: f64,
}
#[derive(Clone, Debug, PartialEq, Default)]
pub struct OrderProduct {
    pub id: String,
    pub image_url: String,
    pub name: String,
    pub quantity: u32,
    pub currency: String,
    pub price: f64,
}
#[derive(Clone, Debug, PartialEq, Default)]
pub struct OrderDetails {
    pub price: OrderPrice,
    pub products: Vec<OrderProduct>,
}
pub type CatalogCursor = String;
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct GetCatalogOptions {
    /// cursor to start from
    pub cursor: Option<CatalogCursor>,
    /// number of products to fetch
    pub limit: Option<u32>,
    pub jid: Option<String>,
}
