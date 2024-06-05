use serde::{Deserialize, Serialize};
use serde_json::{from_value, to_value, Value};

/** ScopeTuple is a packed version of Scope that is used for import/export operations. */
#[derive(Serialize, Deserialize)]
pub struct ScopeTuple (pub String, pub u64, pub Vec<String>, pub Vec<ScopeTuple>);

impl ScopeTuple {
    pub fn as_json(self) -> Value {
        Value::from(self)
    }

    pub fn from_json(value: Value) -> ScopeTuple {
        ScopeTuple::from(value)
    }
}

impl From<Value> for ScopeTuple {
    fn from(value: Value) -> Self {
        return if let Ok(result) = from_value(value) {
            result
        } else {
            panic!("Failed to de-serialize JSON into ScopeTuple.");
        }
    }
}

impl From<ScopeTuple> for Value {
    fn from(value: ScopeTuple) -> Self {
        return if let Ok(result) = to_value(value) {
            result
        } else {
            panic!("Failed to serialize ScopeTuple into JSON.");
        }
    }
}

mod tests {
    use crate::scope::Scope;

    fn validate_scope(left: &Scope, right: &Scope) -> bool {
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

            assert!(validate_scope(&Scope::from(scope.as_tuple()), &scope));
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

        assert!(validate_scope(&Scope::from(scope.as_tuple()), &scope));
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

        assert!(validate_scope(&Scope::from(scope.as_tuple()), &scope));
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

        assert!(validate_scope(&Scope::from(scope.as_tuple()), &scope));
    }

    #[test]
    fn test_json_import_export() {
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

        assert!(validate_scope(&Scope::from(scope.as_tuple()), &scope));

        let json = scope.as_tuple().as_json();
        assert!(json.is_array());
        assert!(validate_scope(&Scope::from_json(json), &scope));
    }
}