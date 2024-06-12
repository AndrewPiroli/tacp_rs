use alloc::string::{String, ToString};
use alloc::vec::Vec;
use alloc::borrow::ToOwned;
use core::net::IpAddr;

#[derive(Debug, Clone, PartialEq)]
pub enum Value {
    Numeric(f64),
    Boolean(bool),
    IPAddr(IpAddr),
    Str(String),
    Empty,
}

impl From<&str> for Value {
    fn from(value: &str) -> Self {
        if value.is_empty() { return Self::Empty }
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

impl Value {
    pub fn as_str(&self) -> Option<&str> {
        if let Self::Str(s) = self {
            Some(s.as_str())
        }
        else { None }
    }
    pub fn as_num(&self) -> Option<f64> {
        if let Self::Numeric(n) = self {
            Some(*n)
        }
        else { None }
    }
    pub fn as_bool(&self) -> Option<bool> {
        if let Self::Boolean(b) = self {
            Some(*b)
        }
        else { None }
    }
    pub fn as_ipaddr(&self) -> Option<IpAddr> {
        if let Self::IPAddr(ip) = self {
            Some(*ip)
        }
        else { None }
    }
    pub fn is_empty(&self) -> bool {
        self == &Value::Empty
    }
}

#[derive(Debug, Clone)]
pub struct ArgValPair {
    pub argument: String,
    pub value: Value,
    pub optional: bool,
}

impl TryFrom<String> for ArgValPair {
    type Error = super::TacpErr;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        if let Some(seplen) = value.find('=') {
            let (arg, mut val) = value.split_at(seplen);
            // remove separator
            if val.len() == 1 {
                val = "";
            }
            else {
                val = &val[1..];
            }
            return Ok(
                Self {
                    argument: arg.to_owned(),
                    value: Value::from(val),
                    optional: false,
                }
            )
        }
        if let Some(seplen) = value.find('*') {
            let (arg, mut val) = value.split_at(seplen);
            if val.len() == 1 {
                val = "";
            }
            else {
                val = &val[1..];
            }
            return Ok(
                Self {
                    argument: arg.to_owned(),
                    value: Value::from(val),
                    optional: true,
                }
            )
        }
        Err(super::TacpErr::ParseError("No valid separator ('=' or '*') found!".to_owned()))
    }
}
impl ArgValPair {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut res = Vec::with_capacity(256);
        res.extend(self.argument.as_bytes());
        if self.optional {
            res.push(b'*');
        }
        else {
            res.push(b'=');
        }
        match &self.value {
            Value::Numeric(num) => {res.extend(num.to_string().as_bytes());},
            Value::Boolean(tf) => {res.extend(tf.to_string().as_bytes());},
            Value::IPAddr(ip) => {res.extend(ip.to_string().as_bytes());},
            Value::Str(s) => {res.extend(s.as_bytes());},
            Value::Empty => {},
        }
        res
    }
}