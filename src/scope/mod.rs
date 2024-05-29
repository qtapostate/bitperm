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

    pub fn add_scope(&mut self, name: &str) -> Result<&mut Scope, ErrorKind> {
        return match self.validate_name(&name.to_string()) {
            Ok(_) => {
                let new_scope = Scope::new(name);
                self.scopes.insert(name.to_string(), new_scope);

                Ok(self)
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

    /** Get a permission by name. */
    pub fn permission(&mut self, name: &str) -> Option<&mut Permission> {
        if self.permissions.is_empty() {
            return None
        }

        self.permissions.get_mut(name)
    }

    /** Get a scope by name. */
    pub fn scope(&mut self, name: &str) -> Option<&mut Scope> {
        if self.scopes.is_empty() {
            return None
        }

        self.scopes.get_mut(name)
    }

    /**
        Get the numeric value for permissions granted in the current scope,
        not including any child scopes, as an unsigned 64-bit integer.
     */
    pub fn as_u64(&self) -> u64 {
        let mut value: u64 = 0;

        for permission in self.permissions.values() {
            if permission.has() {
                value = value | permission.value;
            }
        }

        return value;
    }

    pub fn as_tuple(&self) -> (String, u64) {
        return (self.name.clone(), self.as_u64());
    }
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

    #[test]
    fn test_get_permission_exists_some() {
        match
            Scope::new("TEST_SCOPE")
                .add_permission("TEST_PERMISSION") {
            Ok(scope) => {
                let perm = scope.permission("TEST_PERMISSION");

                assert_eq!(perm.is_some(), true);
            }
            Err(_) => assert!(false)
        }
    }

    #[test]
    fn test_get_permission_missing_none() {
        let mut scope = Scope::new("TEST_SCOPE");
        let perm = scope.permission("TEST_PERMISSION");

        assert_eq!(perm.is_none(), true);
    }

    #[test]
    fn test_get_child_scope_exists_some() {
        match
            Scope::new("TEST_SCOPE")
                .add_scope("TEST_CHILD_SCOPE") {
                Ok(scope) => {
                    let child_scope = scope.scope("TEST_CHILD_SCOPE");

                    assert_eq!(child_scope.is_some(), true);
                }
                Err(_) => assert!(false)
            }
    }

    #[test]
    fn test_get_child_scope_missing_none() {
        let mut scope = Scope::new("TEST_SCOPE");
        let child = scope.scope("TEST_CHILD_SCOPE");

        assert_eq!(child.is_none(), true);
    }

    #[test]
    pub fn test_as_u64_calculate_single() {
        match Scope::new("TEST_SCOPE")
            .add_permission("TEST_PERMISSION_1") {
            Ok(scope) => {
                // find the permission and pass the borrowed variable along the chain to grant
                match scope.permission("TEST_PERMISSION_1").and_then(|mut perm| {
                    // grant the permission
                    return match perm.grant() {
                        Ok(p) => Some(p),
                        _ => None
                    }
                }) {
                    Some(p) => {
                        // check successful grant
                        assert_eq!(p.has_permission, true);
                        assert_eq!(p.has(), true);
                    }
                    _ => assert!(false),
                }

                let value = scope.as_u64();
                assert_eq!(value, 1);
            }
            _ => assert!(false)
        }
    }
}