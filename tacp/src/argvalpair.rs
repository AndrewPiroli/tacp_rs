//! TACACS+ Argument-Value Pairs
//!
//! TACACS+ values are stringly typed. This module attempts to parse things in a more reasonable
//! way while still following the RFC
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use alloc::borrow::ToOwned;
use core::net::IpAddr;

use crate::TacpErr;

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
        // This is not a bug!
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

impl TryFrom<&str> for ArgValPair {
    type Error = super::TacpErr;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
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

impl TryFrom<&String> for ArgValPair {
    type Error = TacpErr;

    fn try_from(value: &String) -> Result<Self, Self::Error> {
        Self::try_from(value.as_str())
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

pub struct ArgValPairCopyIter<'a> {
    current: u16,
    data_idx: usize,
    limit: &'a u8,
    lengths: &'a [u8],
    data: &'a [u8],
}
impl<'a> ArgValPairCopyIter<'a> {
    pub fn new(limit: &'a u8, lengths: &'a [u8], data: &'a [u8]) -> Self {
        Self {
            current: 0,
            data_idx: 0,
            limit,
            lengths,
            data,
        }
    }
}

impl Iterator for ArgValPairCopyIter<'_> {
    type Item = Result<ArgValPair, TacpErr>;
    fn next(&mut self) -> Option<Self::Item> {
        if self.current < *self.limit as u16 {
            let len = self.lengths[self.current as usize] as usize;
            let new_idx = self.data_idx + len;
            let ret = String::from_utf8_lossy(&self.data[self.data_idx..new_idx]).into_owned();
            self.data_idx = new_idx;
            self.current += 1;
            return Some(ArgValPair::try_from(&ret));
        }
        None
    }
}