use crate::permission::error::PermissionError;
use crate::scope::error::ScopeError;

pub enum ErrorKind {
    PermissionError(PermissionError),
    ScopeError(ScopeError)
}