pub mod error;

use std::collections::HashMap;
use crate::common::error::ErrorKind;
use crate::permission::Permission;
use crate::scope::error::{ScopeError, ScopeErrorCase};

pub struct Scope {
    name: String,
    permissions: HashMap<String, Permission>,
    next_permission_shift: u8,
    scopes: HashMap<String, Scope>,
}

impl Scope {
    pub fn new(name: &str) -> Scope {
        return Scope {
            name: name.to_string(),
            permissions: HashMap::new(),
            next_permission_shift: 0,
            scopes: HashMap::new()
        }
    }

    /** Find a permission within this user scope and **/
    pub fn add_permission(&mut self, name: &str) -> Result<&mut Scope, ErrorKind> {
        return match self.validate_name(&name.to_string()) {
            Ok(_) => {
                let new_perm = Permission::new(name, self.next_permission_shift);

                return match new_perm {
                    Ok(perm) => {
                        self.permissions.insert(name.to_string(), perm);
                        self.next_permission_shift = self.next_permission_shift + 1;
                        return Ok(self);
                    },
                    Err(err) => Err(err)
                }
            },
            Err(err) => Err(err)
        }
    }

    /** Verify that the name given is not already contained within existing. **/
    pub fn validate_name(&self, name: &String) -> Result<(), ErrorKind> {
        let perm_unique = !self.permissions.is_empty() && self.permissions.contains_key(name);
        let scope_unique = !self.scopes.is_empty() && self.scopes.contains_key(name);

        return match (!perm_unique, !scope_unique) {
            (true, true) => Ok(()),
            (false, true) => Err(ErrorKind::ScopeError(ScopeError::new(ScopeErrorCase::PermissionExists, name))),
            (true, false) => Err(ErrorKind::ScopeError(ScopeError::new(ScopeErrorCase::ScopeExists, name))),
            (false, false) => Err(ErrorKind::ScopeError(ScopeError::new(ScopeErrorCase::BothExist, name)))
        }
    }

    // pub fn permission(name: &str) -> Result<&Permission, ErrorKind> {
    //
    // }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_scope() {
        let scope = Scope::new("TEST_SCOPE");

        assert_eq!(scope.name, "TEST_SCOPE".to_string());
        assert_eq!(scope.scopes.is_empty(), true);
        assert_eq!(scope.permissions.is_empty(), true);
    }

    #[test]
    fn test_scope_add_permission_ok() {
        let mut scope = Scope::new("TEST_SCOPE");

        assert_eq!(scope.name, "TEST_SCOPE".to_string());
        assert_eq!(scope.scopes.is_empty(), true);
        assert_eq!(scope.permissions.is_empty(), true);

        if let Ok(_) = scope.add_permission("TEST_PERMISSION") {
            assert_eq!(scope.permissions.len(), 1usize); // ensure that we have grown the vector by 1
        } else {
            assert!(false);
        }
    }

    #[test]
    fn test_scope_add_permission_ok_multiple() {
        let mut scope = Scope::new("TEST_SCOPE");

        assert_eq!(scope.name, "TEST_SCOPE".to_string());
        assert_eq!(scope.scopes.is_empty(), true);
        assert_eq!(scope.permissions.is_empty(), true);

        let mut i: usize = 0;
        let max: usize = 50;

        // create 31 unique permission items
        loop {
            // continue adding until we have 31 items
            if i >= max {
                break;
            }

            let name = format!("TEST_PERMISSION_{}", i + 1);
            match scope.add_permission(name.as_str()).and_then(|sc| {
                match sc.permissions.get(name.as_str()) {
                    Some(perm) => {
                        assert_eq!(perm.name, name);
                        assert_eq!(perm.value, 1 << (i as u64));
                    },
                    _ => assert!(false)
                }
                Ok(sc)
            }) {
                Ok(sc) => {
                    assert_eq!(sc.permissions.get(name.as_str()).is_some(), true);
                },
                Err(kind) => match kind {
                    ErrorKind::PermissionError(err) => eprintln!("{}", err),
                    ErrorKind::ScopeError(err) => eprintln!("{}", err)
                }
            }

            i = i + 1
        }

        // check that all 31 are there and properly named
        assert_eq!(scope.permissions.len(), max);
    }

    #[test]
    fn test_scope_add_permission_duplicate() {
        match
            Scope::new("TEST_SCOPE")
                .add_permission("TEST_PERMISSION")
                .and_then(|sc| {
                    return match sc.add_permission("TEST_PERMISSION") {
                        Ok(ok) => Ok(ok),
                        Err(err) => Err(err)
                    }
                }){
                    Ok(_) => assert!(false), // always fail here because we shouldn't succeed on a duplicate
                    Err(err) => match err {
                        ErrorKind::PermissionError(_) => assert!(false),
                        ErrorKind::ScopeError(_) => assert!(true) // expect this error
                    }
        }
    }
}