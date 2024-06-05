pub mod error;

use std::collections::HashMap;
use crate::common::error::ErrorKind;
use crate::permission::{Permission};
use crate::scope::error::{ScopeError, ScopeErrorCase};

pub struct Scope {
    name: String,
    permissions: HashMap<String, Permission>,
    next_permission_shift: u8,
    scopes: HashMap<String, Scope>,
}

pub struct ScopeTuple (String, u64, Vec<String>, Vec<ScopeTuple>);

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

    pub fn as_tuple(&self) -> ScopeTuple {
        let mut permissions_vector: Vec<String> = vec![];
        let mut scopes_vector: Vec<ScopeTuple> = vec![];

        let mut i = 0;
        for (name,_) in &self.permissions {
            permissions_vector.insert(i, name.clone());
            i += 1;
        }

        i = 0;
        for (_, scope) in &self.scopes {
            scopes_vector.insert(i, scope.as_tuple()); // recursive collapse
        }

        return ScopeTuple (self.name.clone(), self.as_u64(), permissions_vector, scopes_vector);
    }
}

impl Clone for ScopeTuple {
    fn clone(&self) -> Self {
        return ScopeTuple(self.0.clone(), self.1.clone(), self.2.clone(), self.3.clone());
    }
}

impl From<ScopeTuple> for Scope {
    fn from(ScopeTuple (name, permission_number, permission_names, child_scopes): ScopeTuple) -> Self {
        let mut permissions = HashMap::<String, Permission>::new();
        let mut scopes = HashMap::<String, Scope>::new();

        let mut i = 0;
        let permission_count = permission_names.len();
        let scope_count = child_scopes.len();

        // populate a hashmap with k-v pairs of (name, permission)
        let r_expand_permissions: Result<(), ()> = loop {
            if i >= permission_count {
                break Ok(());
            }

            if let Ok(mut perm) = Permission::new(permission_names[i].as_str(), (i + 1) as u8) {
                if permission_number & (2 << i) == (2 << i) {
                    let _ = perm.grant(); // we have the numeric amount, so grant the permission in expanded form
                }

                permissions.insert(permission_names[i].clone(), perm);
            } else {
                break Err(());
            }

            i += 1;
        };

        if r_expand_permissions.is_err() {
            panic!("Unable to transform scope tuple into scope: failed to expand permissions.")
        }

        i = 0;
        let r_expand_scopes: Result<(), ()> = loop {
            if i >= scope_count {
                break Ok(())
            }

            let ScopeTuple (n,p, r, c) = child_scopes[i].clone();
            let child = Scope::from(ScopeTuple(n.clone(), p, r, c));

            scopes.insert(n.to_string(), child);

            i += 1;
        };

        if r_expand_scopes.is_err() {
            panic!("Unable to transform scope tuple into scope: failed to expand child scopes.")
        }

        let mut scope = Scope::new(name.as_str());
        scope.permissions = permissions;
        scope.next_permission_shift = permission_count as u8;
        scope.scopes = scopes;

        scope // final constructed scope is expanded from tuple form
    }
}

#[cfg(test)]
mod tests {
    use crate::permission::MAX_VALUE;
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
    fn test_scope_create_and_add_permission() {
        let mut scope = Scope::new("TEST_SCOPE");
        if let Ok(sc) = scope.add_permission("TEST_PERMISSION") {
            assert_eq!(sc.permissions.len(), 1usize);
            assert_eq!(sc.permission("TEST_PERMISSION").is_some(), true);
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
    fn test_scope_add_permission_ok_multiple_simple() {
        let mut scope = Scope::new("TEST_SCOPE");

        if let Ok(_) = scope
            .add_permission("READ")
            .and_then(|sc| sc.add_permission("WRITE"))
            .and_then(|sc| sc.add_permission("EXECUTE")) {
            assert_eq!(scope.permissions.len(), 3usize);
        } else {
            assert!(false);
        }
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
    fn test_add_child_scope_simple() {
        let mut scope = Scope::new("TEST_SCOPE");

        if let Ok(_) = scope.add_scope("CHILD_SCOPE") {
            if let Some(child_scope) = scope.scope("CHILD_SCOPE") {
                // do something with the child scope
                assert_eq!(child_scope.name, "CHILD_SCOPE");
                assert_eq!(child_scope.scopes.is_empty(), true);
                assert_eq!(child_scope.permissions.is_empty(), true);
            }
        } else {
            // failed to create the child scope
            assert!(false);
        }
    }

    #[test]
    fn test_add_child_and_add_permissions_to_child_scope() {
        let mut scope = Scope::new("TEST_SCOPE");

        if let Ok(_) = scope.add_scope("CHILD_SCOPE") {
            if let Some(child_scope) = scope.scope("CHILD_SCOPE") {
                // do something with the child scope
                assert_eq!(child_scope.name, "CHILD_SCOPE");
                assert_eq!(child_scope.scopes.is_empty(), true);
                assert_eq!(child_scope.permissions.is_empty(), true);

                if let Ok(_) = child_scope.add_permission("TEST_CHILD_PERMISSION") {
                    assert_eq!(child_scope.permissions.len(), 1usize);
                    assert_eq!(child_scope.permission("TEST_CHILD_PERMISSION").is_some(), true);
                }
            }
        } else {
            // failed to create the child scope
            assert!(false);
        }
    }

    /**
        Get the final result given a number of added permissions
        assuming all permissions in a scope are granted.
     */
    fn get_test_scope_value(number_added: u8) -> u64 {
        return 2u64.pow(number_added as u32) - 1;
    }

    #[test]
    fn test_util_get_test_scope_value() {
        // ensure the util function above works as expected
        let mut i = 0;
        let max_iterations = 16;
        loop {
            if i > max_iterations {
                break;
            }

            // double the previous value and add 1
            let value = get_test_scope_value(i);
            let mut expected = 0;
            if i > 0 {
                expected = get_test_scope_value(i - 1) * 2 + 1;
            }

            // println!("{} bit = max {} [expecting: {}]", i, value, expected);

            assert_eq!(value, expected);
            assert!(value < MAX_VALUE);

            i = i + 1;
        }
    }

    #[test]
    fn test_as_u64_calculate_single() {
        match Scope::new("TEST_SCOPE")
            .add_permission("TEST_PERMISSION_1") {
            Ok(scope) => {
                // find the permission and pass the borrowed variable along the chain to grant
                match scope.permission("TEST_PERMISSION_1").and_then(|perm| {
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
                assert_eq!(value, get_test_scope_value(scope.permissions.len() as u8));
            }
            _ => assert!(false)
        }
    }

    #[test]
    fn test_add_and_grant_multiple_and_get_calculated_value() {
        let mut scope = Scope::new("TEST_SCOPE");

        if let Ok(_) = scope
            .add_permission("READ")
            .and_then(|sc| sc.add_permission("WRITE"))
            .and_then(|sc| sc.add_permission("EXECUTE")) {
            assert_eq!(scope.permissions.len(), 3usize);

            for perm in vec!["READ", "WRITE", "EXECUTE"] {
                scope.permission(perm).and_then(|p| {
                    return if let Ok(granted) = p.grant() {
                        Some(granted)
                    } else {
                        None
                    }
                });
            }

            let permissions_numeric = scope.as_u64();

            assert_eq!(permissions_numeric, get_test_scope_value(3));

        } else {
            assert!(false);
        }
    }

    #[test]
    fn test_as_u64_calculate_multiple() {
        let mut scope = Scope::new("TEST_SCOPE");
        let mut i = 0;
        let max = 53;

        loop {
            if i == max {
                break;
            }

            let name = format!("TEST_PERMISSION_{}", i);
            match scope.add_permission(name.as_str()) {
                Ok(_) => {
                    // find the permission and pass the borrowed variable along the chain to grant
                    scope.permission(name.as_str()).and_then(|perm| {
                        // grant the permission
                        return match perm.grant() {
                            Ok(p) => Some(p),
                            _ => {
                                assert!(false);
                                None
                            }
                        }
                    });
                }
                _ => {
                    panic!("Failed to grant permission '{}'", name);
                }
            }

            i = i + 1;
        }

        assert_eq!(scope.as_u64(), get_test_scope_value(scope.permissions.len() as u8));
    }

    fn validate_scope(left: Scope, right: Scope) -> bool {
        if !left.name.eq(right.name.as_str()) {
            eprintln!("scope name encoded to tuple ('{}') does not equal expected value ('{}')", left.name, right.name.as_str());
            return false;
        }
        if left.as_u64() != right.as_u64() {
            eprintln!("permission number encoded to tuple ({}) does not equal expected value ({})", left.as_u64(), right.as_u64());
            return false;
        }
        if left.permissions.len() != right.permissions.len() {
            eprintln!("permissions length encoded to tuple ({}) does not equal expected value ({})", left.permissions.len(), right.permissions.len());
            return false;
        }
        if left.scopes.len() != right.scopes.len() {
            eprintln!("scopes length encoded to tuple ({}) does not equal expected value ({})", left.scopes.len(), right.scopes.len());
            return false;
        }

        let mut i = 0;
        for permission in left.permissions.values() {
            if let Some(expected_permission) = right.permissions.get(permission.name.as_str()) {
                if !permission.name.as_str().eq(permission.name.as_str()) {
                    eprintln!("name of permission at index {} ('{}') does not match expected value ('{}')", i, permission.name, expected_permission.name);
                    return false;
                }
            } else {
                eprintln!("permission at index {} ('{}') was not found in scope", i, permission.name);
                return false;
            }

            i = i + 1;
        }

        // for child_scope in left.scopes.values() {
        //     if let Some(expected_child_scope) = right.scopes.get(&child_scope.name) {
        //         return validate_scope(child_scope, expected_child_scope);
        //     }
        // }

        return true;
    }

    #[test]
    fn test_export_tuple_with_permissions_no_child_scopes() {
        let mut scope = Scope::new("USER");

        if let Ok(_) = scope
            .add_permission("CREATE")
            .and_then(|sc| sc.add_permission("READ"))
            .and_then(|sc| sc.add_permission("UPDATE"))
            .and_then(|sc| sc.add_permission("DELETE"))
            .and_then(|sc| sc.add_permission("EXECUTE")){
            assert_eq!(scope.permissions.len(), 5usize);

            // grant some of the permissions but not all of them
            for perm in vec!["CREATE", "READ", "EXECUTE"] {
                scope.permission(perm).and_then(|p| {
                    return if let Ok(granted) = p.grant() {
                        Some(granted)
                    } else {
                        None
                    }
                });
            }

            assert!(validate_scope(Scope::from(scope.as_tuple()), scope));
        } else {
            assert!(false);
        }
    }

    #[test]
    fn test_export_tuple_with_child_scopes_no_permissions() {
        let mut scope = Scope::new("USER");

        // add a child scope
        if let Ok(_) = scope.add_scope("CHILD_SCOPE") {
            assert_eq!(scope.scope("CHILD_SCOPE").is_some(), true);
        } else {
            assert!(false);
        }

        assert!(validate_scope(Scope::from(scope.as_tuple()), scope));
    }

    #[test]
    fn test_export_tuple_with_child_scopes_and_root_permissions_no_child_permissions() {
        let mut scope = Scope::new("USER");

        // add a child scope
        if let Ok(_) = scope.add_scope("CHILD_SCOPE") {
            assert_eq!(scope.scope("CHILD_SCOPE").is_some(), true);
        } else {
            assert!(false);
        }

        // add permissions to containing scope
        if let Ok(_) = scope
            .add_permission("CREATE")
            .and_then(|sc| sc.add_permission("READ"))
            .and_then(|sc| sc.add_permission("UPDATE"))
            .and_then(|sc| sc.add_permission("DELETE"))
            .and_then(|sc| sc.add_permission("EXECUTE")){
            assert_eq!(scope.permissions.len(), 5usize);

            // grant some of the permissions but not all of them
            for perm in vec!["CREATE", "READ", "EXECUTE"] {
                scope.permission(perm).and_then(|p| {
                    return if let Ok(granted) = p.grant() {
                        Some(granted)
                    } else {
                        None
                    }
                });
            }
        } else {
            assert!(false);
        }

        assert!(validate_scope(Scope::from(scope.as_tuple()), scope));
    }

    #[test]
    fn test_export_tuple_with_child_scopes_and_root_permissions_and_child_permissions() {
        let mut scope = Scope::new("USER");

        // add a child scope
        if let Ok(_) = scope.add_scope("CHILD_SCOPE") {
            assert_eq!(scope.scope("CHILD_SCOPE").is_some(), true);
        } else {
            assert!(false);
        }

        if let Some(child_scope) = scope.scope("CHILD_SCOPE") {
            if let Ok(_) = child_scope.add_permission("CREATE") {
                assert_eq!(child_scope.permissions.len(), 1usize);
            }
        } else {
            assert!(false);
        }

        // add permissions to containing scope
        if let Ok(_) = scope
            .add_permission("CREATE")
            .and_then(|sc| sc.add_permission("READ"))
            .and_then(|sc| sc.add_permission("UPDATE"))
            .and_then(|sc| sc.add_permission("DELETE"))
            .and_then(|sc| sc.add_permission("EXECUTE")){
            assert_eq!(scope.permissions.len(), 5usize);

            // grant some of the permissions but not all of them
            for perm in vec!["CREATE", "READ", "EXECUTE"] {
                scope.permission(perm).and_then(|p| {
                    return if let Ok(granted) = p.grant() {
                        Some(granted)
                    } else {
                        None
                    }
                });
            }
        } else {
            assert!(false);
        }

        assert!(validate_scope(Scope::from(scope.as_tuple()), scope));
    }

}