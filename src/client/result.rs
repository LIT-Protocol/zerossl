use std::collections::HashMap;
use std::fmt::{Display, Formatter};
use serde::{Deserialize, Serialize};

pub trait Resp {
    fn is_ok(&self) -> bool;
    fn err_msg(&self) -> Option<ErrorMsg>;

    fn err_msg_string(&self) -> Option<String> {
        if let Some(err_msg) = self.err_msg() {
            return Some(format!("{}", err_msg));
        }

        None
    }

    fn to_err(&self) -> crate::error::Error {
        crate::error::request(format!("request failed"), self.err_msg_string())
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ResultStatus {
    success: Option<bool>,
    error: Option<ErrorMsg>
}

impl Resp for ResultStatus {
    fn is_ok(&self) -> bool {
        if let Some(success) = self.success {
            return success
        }

        true
    }

    fn err_msg(&self) -> Option<ErrorMsg> {
        if let Some(error) = self.error.as_ref() {
            return Some(error.clone())
        }

        None
    }
}

// Did you know 'success' can be true AND 1. WTF.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ResultStatusAlt {
    success: Option<u8>,
}

impl Resp for ResultStatusAlt {
    fn is_ok(&self) -> bool {
        if let Some(success) = self.success {
            return success == 1
        }

        true
    }

    fn err_msg(&self) -> Option<ErrorMsg> {
        None
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ErrorMsg {
    code: Option<i32>,
    #[serde(rename = "type")]
    typ: Option<String>,
    details: Option<String>
}

impl Display for ErrorMsg {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str("zerossl error msg")?;

        if let Some(code) = &self.code {
            write!(f, ": {}", code)?;
        }

        if let Some(typ) = &self.typ {
            write!(f, ": {}", typ)?;
        }

        if let Some(details) = &self.details {
            write!(f, ": {}", details)?;
        }

        Ok(())
    }
}