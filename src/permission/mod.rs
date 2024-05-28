pub mod error;

use crate::common::error::ErrorKind;
use crate::permission::error::{PermissionErrorCase, PermissionErrorMetadata};
use crate::permission::error::PermissionError;

pub struct Permission {
    pub name: String,
    pub value: u64
}

const MAX_VALUE: u64 = 9007199254740991; // = JsNumber.MAX_SAFE_INTEGER

impl Permission {
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
                value: 1 << validated_shift
            }),
            Err(err) => Err(err),
        };
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
    fn test_panic_exceeded_max_shift() {
        let _ = Permission::new("TEST_PERMISSION", 35);
    }

    #[test]
    fn test_panic_invalid_value_not_power_of_two() {
        // value that is not 0, 1, or a power of 2
        let invalid_value: u64 = (1 << 26) + 17; // 67108881
        let ret = validate_value(&"RANDOM_NAME".to_string(), &invalid_value);

        assert!(ret.is_err())
    }

    #[test]
    fn test_panic_invalid_value_zero() {
        // value of zero should fail
        let invalid_value: u64 = 0;
        let ret = validate_value(&"RANDOM_NAME".to_string(), &invalid_value);

        assert!(ret.is_err())
    }

    #[test]
    fn test_panic_valid_value_one() {
        // value that is not 0, 1, or a power of 2
        let valid_value: u64 = 1;
        let ret = validate_value(&"RANDOM_NAME".to_string(), &valid_value);

        assert!(ret.is_ok())
    }
}