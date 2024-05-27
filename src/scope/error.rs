use std::fmt;
use std::fmt::{Debug, Display, Formatter};

pub struct ScopeError {
    name: String,
    case: ScopeErrorCase,
}

pub enum ScopeErrorCase {
    PermissionExists,
    ScopeExists,
    BothExist
}

const ERROR_NAME: &str = "ScopeError";

const UNIQUE_NAME_ERROR_PERMISSION_EXISTS: &str = "is already defined within permissions";
const UNIQUE_NAME_ERROR_SCOPE_EXISTS: &str = "is already defined within scope";
const UNIQUE_NAME_ERROR_BOTH_EXIST: &str = "is already defined within permissions and scope";

impl ScopeError {
    pub fn new(case: ScopeErrorCase, name: &String) -> ScopeError {
        return ScopeError {
            name: name.clone(),
            case
        };
    }
}

fn format_error_message(f: &mut Formatter<'_>, case: &ScopeErrorCase, name: &String) -> fmt::Result {
    let err: String = match *case {
        ScopeErrorCase::PermissionExists => format!("{}: name '{}' {}", ERROR_NAME, name, UNIQUE_NAME_ERROR_PERMISSION_EXISTS),
        ScopeErrorCase::ScopeExists => format!("{}: name '{}' {}", ERROR_NAME, name, UNIQUE_NAME_ERROR_SCOPE_EXISTS),
        ScopeErrorCase::BothExist => format!("{}: name '{}' {}", ERROR_NAME, name, UNIQUE_NAME_ERROR_BOTH_EXIST),
    };

    write!(f, "{}", err)
}

impl Debug for ScopeError {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        format_error_message(f, &self.case, &self.name)
    }
}

impl Display for ScopeError {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        format_error_message(f, &self.case, &self.name)
    }
}

impl std::error::Error for ScopeError {}
