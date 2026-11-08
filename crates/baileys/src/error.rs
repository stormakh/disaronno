//! Error type that matches the fields Baileys reads from a Boom error.
use std::fmt;
use waproto::pb::Json;
#[derive(Clone, Debug, PartialEq, Default)]
pub struct Boom {
    pub message: String,
    pub status_code: Option<u16>,
    /// Marks a missing app-state key, as `data.isMissingKey` does.
    pub is_missing_key: bool,
    /// Same as `error.name === "TypeError"`: a required field was missing, where JavaScript reads a property of null.
    pub is_type_error: bool,
    /// The `data` option of a Boom.
    pub data: Option<Json>,
}
impl Boom {
    pub fn new(m: impl Into<String>) -> Boom {
        Boom { message: m.into(), status_code: None, is_missing_key: false, is_type_error: false, data: None }
    }
    pub fn status(m: impl Into<String>, code: u16) -> Boom {
        Boom { message: m.into(), status_code: Some(code), is_missing_key: false, is_type_error: false, data: None }
    }
    pub fn with_data(m: impl Into<String>, data: Json) -> Boom {
        Boom { message: m.into(), status_code: None, is_missing_key: false, is_type_error: false, data: Some(data) }
    }
    pub fn type_error(m: impl Into<String>) -> Boom {
        Boom { is_type_error: true, ..Boom::new(m) }
    }
    /// Same as `output.statusCode`: a Boom without a code has 500.
    pub fn output_status_code(&self) -> u16 {
        self.status_code.unwrap_or(500)
    }
}
impl fmt::Display for Boom {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}
impl std::error::Error for Boom {}
impl From<waproto::pb::DecodeError> for Boom {
    fn from(e: waproto::pb::DecodeError) -> Boom {
        Boom::new(*e.0)
    }
}
pub type Result<T> = std::result::Result<T, Boom>;
