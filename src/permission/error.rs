use std::fmt;
use std::fmt::{Debug, Display, Formatter};
use crate::permission::MAX_VALUE;

pub struct PermissionError {
    name: String,
    case: PermissionErrorCase,
    metadata: PermissionErrorMetadata
}

pub enum PermissionErrorCase {
    MaxValue,
    InvalidValue
}

pub struct PermissionErrorMetadata {
    pub(crate) shift: Option<u8>
}

impl PermissionErrorMetadata {
    pub fn new() -> PermissionErrorMetadata {
        return PermissionErrorMetadata {
            shift: None,
        }
    }
}

impl PermissionError {
    pub fn new(case: PermissionErrorCase, permission_name: &String, error_metadata: PermissionErrorMetadata) -> PermissionError {
        return PermissionError {
            name: (*permission_name).clone(),
            case,
            metadata: error_metadata
        }
    }
}

const ERROR_NAME: &str = "PermissionError";

fn format_error_message(f: &mut Formatter<'_>, case: &PermissionErrorCase, name: &String, metadata: &PermissionErrorMetadata) -> fmt::Result {
    let err: String = match *case {
        PermissionErrorCase::MaxValue => {
            if let Some(shift_value) = (*metadata).shift {
                format!("{}: parameter 'shift' ({}) for permission '{}' exceeded maximum safe value ({}).",
                        ERROR_NAME,
                        shift_value,
                        *name,
                        MAX_VALUE)
            } else {
                // need to panic here because we're missing the necessary properties to even parse an error
                panic!("{} - PANIC: Unable to format error message due to missing metadata property 'shift'", ERROR_NAME);
            }
        },
        PermissionErrorCase::InvalidValue => format!("{}: permission '{}' evaluated to an illegal value that is not 1 or a power of 2.", ERROR_NAME, *name)
    };

    write!(f, "{}", err)
}

impl Debug for PermissionError {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        format_error_message(f, &self.case, &self.name, &self.metadata)
    }
}

impl Display for PermissionError {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        format_error_message(f, &self.case, &self.name, &self.metadata)
    }
}

impl std::error::Error for PermissionError {}

