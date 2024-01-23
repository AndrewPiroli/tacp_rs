
use std::net::IpAddr;

#[derive(Debug, Clone)]
pub enum Value {
    Numeric(f64),
    Boolean(bool),
    IPAddr(IpAddr),
    Str(String),
    Empty,
}
impl From<&str> for Value {
    fn from(value: &str) -> Self {
        if value.len() == 0 { return Self::Empty }
        if value == "true" || value == "false" { return Self::Boolean(value == "true") }
        if let Ok(ip) = value.parse::<IpAddr>() {
            return Self::IPAddr(ip);
        }
        if let Ok(num) = value.parse::<f64>() {
            return Self::Numeric(num);
        }
        Self::Str(value.to_owned())
    }
}

#[derive(Debug, Clone)]
pub struct ArgValPair {
    pub argument: String,
    pub value: Value,
    pub optional: bool,
}

impl TryFrom<String> for ArgValPair {
    type Error = &'static str;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        if let Some(seplen) = value.find('=') {
            let (arg, val) = value.split_at(seplen);
            return Ok(
                Self {
                    argument: arg.to_owned(),
                    value: Value::from(val),
                    optional: true,
                }
            )
        }
        if let Some(seplen) = value.find('*') {
            let (arg, val) = value.split_at(seplen);
            return Ok(
                Self {
                    argument: arg.to_owned(),
                    value: Value::from(val),
                    optional: false,
                }
            )
        }
        Err("No valid separator ('=' or '*') found!")
    }
}