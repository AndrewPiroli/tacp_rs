//! TACACS+ Argument-Value Pairs
//!
//! TACACS+ values are stringly typed. This module attempts to parse things in a more reasonable
//! way while still following the RFC
use alloc::string::String;
use core::net::IpAddr;

use crate::TacpErr;

#[derive(Debug, Clone, PartialEq)]
pub enum Value<'a> {
    Numeric(f64),
    Boolean(bool),
    IPAddr(IpAddr),
    Str(&'a str),
    Empty,
}

impl<'a> From<&'a str> for Value<'a> {
    fn from(value: &'a str) -> Self {
        if value.is_empty() { return Self::Empty }
        // This is not a bug!
        if value == "true" || value == "false" { return Self::Boolean(value == "true") }
        if let Ok(ip) = value.parse::<IpAddr>() {
            return Self::IPAddr(ip);
        }
        if let Ok(num) = value.parse::<f64>() {
            return Self::Numeric(num);
        }
        Self::Str(value)
    }
}

impl Value<'_> {
    pub fn as_str(&self) -> Option<&str> {
        if let Self::Str(s) = self {
            Some(s)
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

impl core::fmt::Display for Value<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Value::Numeric(num) => {
                write!(f, "{num}")
            },
            Value::IPAddr(ip) => {
                write!(f, "{ip}")
            },
            Value::Boolean(tf) => {
                match tf {
                    true => f.write_str("true"),
                    false => f.write_str("false"),
                }
            },
            Value::Str(s) => {
                f.write_str(s)
            },
            Value::Empty => {Ok(())},
        }
    }
}

#[derive(Debug, Clone)]
pub struct ArgValPair<'arg, 'val> {
    pub argument: &'arg str,
    pub value: Value<'val>,
    pub optional: bool,
}

impl<'a> TryFrom<&'a str> for ArgValPair<'a, 'a> {
    type Error = super::TacpErr;

    fn try_from(value: &'a str) -> Result<Self, Self::Error> {
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
                    argument: arg,
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
                    argument: arg,
                    value: Value::from(val),
                    optional: true,
                }
            )
        }
        Err(super::TacpErr::ParseError("No valid separator ('=' or '*') found!"))
    }
}

impl<'a> TryFrom<&'a String> for ArgValPair<'a, 'a> {
    type Error = TacpErr;

    fn try_from(value: &'a String) -> Result<Self, Self::Error> {
        Self::try_from(value.as_str())
    }
}

impl core::fmt::Display for ArgValPair<'_, '_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}", self.argument)?;
        if self.optional {
            f.write_str("*")?;
        }
        else {
            f.write_str("=")?;
        }
        write!(f, "{}", self.value)
    }
}

pub struct ArgValPairIter<'a> {
    current: u16,
    data_idx: usize,
    limit: u8,
    lengths: &'a [u8],
    data: &'a [u8],
}
impl<'a> ArgValPairIter<'a> {
    pub fn new(limit: u8, lengths: &'a [u8], data: &'a [u8]) -> Self {
        Self {
            current: 0,
            data_idx: 0,
            limit,
            lengths,
            data,
        }
    }
}

impl<'a> Iterator for ArgValPairIter<'a> {
    type Item = Result<ArgValPair<'a, 'a>, TacpErr>;
    fn next(&mut self) -> Option<Self::Item> {
        if self.current < u16::from(self.limit) {
            let len = self.lengths[self.current as usize] as usize;
            let new_idx = self.data_idx + len;
            let ret =  match str::from_utf8(&self.data[self.data_idx..new_idx]) {
                Ok(avp_str) => {
                    Some(ArgValPair::try_from(avp_str))
                },
                Err(e) => {
                    Some(Err(TacpErr::Utf8ConversionError(e)))
                }
            };
            self.data_idx = new_idx;
            self.current += 1;
            return ret;
        }
        None
    }
}