//! Logger trait, in place of pino and ILogger.
use crate::utils::time::{iso_time, now_ms};
use std::io::Write;
use std::sync::{Arc, OnceLock};
use waproto::pb::Json;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum LogLevel {
    Trace = 10,
    Debug = 20,
    Info = 30,
    Warn = 40,
    Error = 50,
    Fatal = 60,
    Silent = 100,
}
impl LogLevel {
    pub fn name(self) -> &'static str {
        match self {
            LogLevel::Trace => "trace",
            LogLevel::Debug => "debug",
            LogLevel::Info => "info",
            LogLevel::Warn => "warn",
            LogLevel::Error => "error",
            LogLevel::Fatal => "fatal",
            LogLevel::Silent => "silent",
        }
    }
}
/// `obj` is the first argument of a pino call. To keep hot paths free, check `is_enabled`
/// before building an object or a formatted message.
pub trait Logger: Send + Sync {
    fn level(&self) -> LogLevel;
    fn child(&self, bindings: &[(&str, &str)]) -> Arc<dyn Logger>;
    /// Writes one record. The level methods call this only when the level is enabled.
    fn log(&self, level: LogLevel, obj: Option<&Json>, msg: &str);
    fn is_enabled(&self, level: LogLevel) -> bool {
        level >= self.level() && level != LogLevel::Silent
    }
    fn at(&self, level: LogLevel, obj: Option<&Json>, msg: &str) {
        if self.is_enabled(level) {
            self.log(level, obj, msg);
        }
    }
    fn trace(&self, msg: &str) {
        self.at(LogLevel::Trace, None, msg)
    }
    fn debug(&self, msg: &str) {
        self.at(LogLevel::Debug, None, msg)
    }
    fn info(&self, msg: &str) {
        self.at(LogLevel::Info, None, msg)
    }
    fn warn(&self, msg: &str) {
        self.at(LogLevel::Warn, None, msg)
    }
    fn error(&self, msg: &str) {
        self.at(LogLevel::Error, None, msg)
    }
    fn trace_obj(&self, obj: &Json, msg: &str) {
        self.at(LogLevel::Trace, Some(obj), msg)
    }
    fn debug_obj(&self, obj: &Json, msg: &str) {
        self.at(LogLevel::Debug, Some(obj), msg)
    }
    fn info_obj(&self, obj: &Json, msg: &str) {
        self.at(LogLevel::Info, Some(obj), msg)
    }
    fn warn_obj(&self, obj: &Json, msg: &str) {
        self.at(LogLevel::Warn, Some(obj), msg)
    }
    fn error_obj(&self, obj: &Json, msg: &str) {
        self.at(LogLevel::Error, Some(obj), msg)
    }
}
#[derive(Clone, Copy, Default)]
pub struct SilentLogger;
impl Logger for SilentLogger {
    fn level(&self) -> LogLevel {
        LogLevel::Silent
    }
    fn child(&self, _bindings: &[(&str, &str)]) -> Arc<dyn Logger> {
        Arc::new(SilentLogger)
    }
    fn log(&self, _level: LogLevel, _obj: Option<&Json>, _msg: &str) {}
}
/// Writes one JSON line per record to stderr, with the fields of a pino record.
#[derive(Clone)]
pub struct StderrLogger {
    pub level: LogLevel,
    bindings: Vec<(String, String)>,
}
impl StderrLogger {
    pub fn new(level: LogLevel) -> StderrLogger {
        StderrLogger { level, bindings: Vec::new() }
    }
}
impl Logger for StderrLogger {
    fn level(&self) -> LogLevel {
        self.level
    }
    fn child(&self, bindings: &[(&str, &str)]) -> Arc<dyn Logger> {
        let mut c = self.clone();
        c.bindings.extend(bindings.iter().map(|(k, v)| (k.to_string(), v.to_string())));
        Arc::new(c)
    }
    fn log(&self, level: LogLevel, obj: Option<&Json>, msg: &str) {
        let mut o = vec![("level".to_string(), Json::Num(level as i32 as f64)), ("time".to_string(), Json::Str(iso_time(now_ms())))];
        for (k, v) in &self.bindings {
            o.push((k.clone(), Json::Str(v.clone())));
        }
        match obj {
            Some(Json::Obj(fields)) => o.extend(fields.iter().cloned()),
            Some(other) => o.push(("data".to_string(), other.clone())),
            None => {}
        }
        o.push(("msg".to_string(), Json::Str(msg.to_string())));
        let mut line = Json::Obj(o).stringify();
        line.push('\n');
        let _ = std::io::stderr().write_all(line.as_bytes());
    }
}
/// The default logger: level info, as `P()` in upstream.
pub fn default_logger() -> Arc<dyn Logger> {
    static L: OnceLock<Arc<dyn Logger>> = OnceLock::new();
    L.get_or_init(|| Arc::new(StderrLogger::new(LogLevel::Info))).clone()
}
