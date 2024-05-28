pub mod error;

use crate::common::error::ErrorKind;
use crate::permission::error::{PermissionErrorCase, PermissionErrorMetadata};
use crate::permission::error::PermissionError;

pub struct Permission {
    pub name: String,
    pub value: u64,
    pub has_permission: bool
}

const MAX_VALUE: u64 = 9007199254740991; // = JsNumber.MAX_SAFE_INTEGER

impl Permission {
    /** Creates a new permission. */
    pub fn new(name: &str, shift: u8) -> Result<Permission, ErrorKind> {
        // verify that the shift is within constraints and create a permission object
        let validated_shift = match validate_shift(&name.to_string(), &shift) {
            Ok(result) => result,
            Err(err) => {
                return Err(err)
            }
        };

        // Verify that the value we created with the shift is legal for bitwise operations
        return match validate_value(&name.to_string(), &(1 << validated_shift)) {
            Ok(_) => Ok(Permission {
                name: name.to_string(),
                value: 1 << validated_shift,
                has_permission: false,
            }),
            Err(err) => Err(err),
        };
    }

    /** Grants the permission to the holder of this reference. */
    pub fn grant(&mut self) -> Result<&mut Permission, ErrorKind> {
        // check if the user has already been granted this permission
        if self.has_permission {
            return Err(
                ErrorKind::PermissionError(
                    PermissionError::new(
                        PermissionErrorCase::GrantError, &self.name, PermissionErrorMetadata::new()
                    )
                )
            );
        }

        self.has_permission = true; // grant

        return Ok(self);
    }

    /** Grants the permission to the holder of this reference. */
    pub fn revoke(&mut self) -> Result<&mut Permission, ErrorKind> {
        // check if the user already lacks this permission
        if !self.has_permission {
            return Err(
                ErrorKind::PermissionError(
                    PermissionError::new(
                        PermissionErrorCase::RevocationError, &self.name, PermissionErrorMetadata::new()
                    )
                )
            );
        }

        self.has_permission = false; // revoke

        return Ok(self);
    }

    pub fn has(&mut self) -> bool {
        return self.has_permission;
    }
}

/** Validate that a bitwise shift is safe to perform both in Rust and JS **/
fn validate_shift(name: &String, shift: &u8) -> Result<u8, ErrorKind> {
    // check that we have not exceeded the safe left-shift that can be performed in the JSVM
    return match (1 << *shift) <= MAX_VALUE {
        true  => Ok(*shift),
        false => Err(ErrorKind::PermissionError(PermissionError::new(
            PermissionErrorCase::MaxValue,
            name,
            PermissionErrorMetadata {
                shift: Some(*shift)
            }
        )))
    }
}

/** Validate that the calculated value of a permission can be evaluated using binary. **/
fn validate_value(name: &String, value: &u64) -> Result<(), ErrorKind> {
    // check that the value is 0, 1, or a power of 2 thereafter
    return match *value == 1 || (*value).is_power_of_two() {
        true => Ok(()),
        false => Err(ErrorKind::PermissionError(
            PermissionError::new(PermissionErrorCase::InvalidValue, name, PermissionErrorMetadata::new())
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_permission_valid() {
        let new_permission = Permission::new("TEST_PERMISSION", 0);

        assert_eq!(new_permission.is_ok(), true);

        if let Ok(perm) = new_permission {
            assert_eq!(perm.name, "TEST_PERMISSION");
            assert_eq!(perm.value, 1 << 0)
        }
    }

    #[test]
    fn test_err_exceeded_max_shift() {
        let mut i = 0;
        let base = 50;
        loop {
            if i >= 10 {
                break;
            }

            match Permission::new("TEST_PERMISSION", base + i) {
                Ok(permission) => {
                    assert!(permission.value <= MAX_VALUE)
                }, // fail because we should not succeed here due to value being too high
                Err(err) => {
                    assert!(i >= 3); // left-shift of 53 and higher should fail
                    match err {
                        ErrorKind::PermissionError(_) => assert!(true), // expect this error
                        ErrorKind::ScopeError(_) => assert!(false) // we should not get back a scope error
                    }
                }
            }

            i = i + 1;
        }
    }

    #[test]
    fn test_err_invalid_value_not_power_of_two() {
        // value that is not 1 or a power of 2
        let invalid_value: u64 = (1 << 26) + 17; // 67108881 is not 1 or a power of 2
        let ret = validate_value(&"RANDOM_NAME".to_string(), &invalid_value);

        assert!(ret.is_err())
    }

    #[test]
    fn test_err_invalid_value_zero() {
        // value of zero should fail
        let invalid_value: u64 = 0;
        let ret = validate_value(&"RANDOM_NAME".to_string(), &invalid_value);

        assert!(ret.is_err())
    }

    #[test]
    fn test_err_valid_value_one() {
        // value that is not 0, 1, or a power of 2
        let valid_value: u64 = 1;
        let ret = validate_value(&"RANDOM_NAME".to_string(), &valid_value);

        assert!(ret.is_ok())
    }

    #[test]
    fn test_grant_ok() {
        match Permission::new("TEST_PERMISSION", 0) {
            Ok(mut p1) => {
                assert_eq!(p1.has_permission, false);
                assert_eq!(p1.has(), false);
                match p1.grant() {
                    Ok(p2) => {
                        assert_eq!(p2.has_permission, true);
                        assert_eq!(p2.has(), true);
                    }
                    Err(_) => assert!(false)
                }
            },
            Err(_) => assert!(false)
        }
    }

    // #[test]
    // fn test_grant_fail_already_granted() {
    //     todo!()
    // }

    #[test]
    fn test_revoke_ok() {
        match Permission::new("TEST_PERMISSION", 0) {
            Ok(mut p1) => {
                p1.has_permission = true;
                assert_eq!(p1.has_permission, true);
                assert_eq!(p1.has(), true);

                match p1.revoke() {
                    Ok(p2) => {
                        assert_eq!(p2.has_permission, false);
                        assert_eq!(p2.has(), false);
                    }
                    Err(_) => assert!(false)
                }
            },
            Err(_) => assert!(false)
        }
    }

}