use std::error::Error;
use std::fmt;
use std::fmt::{Debug, Display, Formatter};

pub struct Permission {
    pub name: String,
    pub value: u64
}

pub struct PermissionShiftError;
pub struct PermissionValueError;

const MAX_SHIFT: u8 = 31; // maximum number of bits we can safely left-shift in an i32
const PERMISSION_SHIFT_ERROR: &str = "PermissionShiftError: shift parameter must not exceed maximum safe left-shift for an i32";
const PERMISSION_VALUE_ERROR: &str = "PermissionValueError: value is not compatible with bitwise operations";

impl Permission {
    pub fn new(name: String, shift: u8) -> Permission {
        // verify that the shift is within constraints and create a permission object
        let validated_shift = match validate_shift(&shift) {
            Ok(value) => value,
            Err(err) => panic!("{}", err),
        };

        // Verify that the value we created with the shift is legal for bitwise operations
        return match validate_value(&(1 << validated_shift)) {
            Ok(_) => Permission {
                name,
                value: 1 << validated_shift
            },
            Err(err) => panic!("{}", err)
        };
    }
}

/** Validate that a bitwise shift is safe to perform both in Rust and JS **/
fn validate_shift(shift: &u8) -> Result<u8, PermissionShiftError> {
    // check that we have not exceeded the safe left-shift that can be performed in the JSVM
    return match *shift <= MAX_SHIFT {
        true  => Ok(*shift),
        false => Err(PermissionShiftError{}),
    }
}

/** Validate that the calculated value of a permission can be evaluated using binary. **/
fn validate_value(value: &u64) -> Result<(), PermissionValueError> {
    // check that the value is 0, 1, or a power of 2 thereafter
    return match *value == 1 || (*value).is_power_of_two() {
        true => Ok(()),
        false => Err(PermissionValueError{})
    }
}

impl Debug for PermissionShiftError {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{}", PERMISSION_SHIFT_ERROR)
    }
}

impl Display for PermissionShiftError {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{}", PERMISSION_SHIFT_ERROR)
    }
}

impl Error for PermissionValueError {}

impl Debug for PermissionValueError {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{}", PERMISSION_VALUE_ERROR)
    }
}

impl Display for PermissionValueError {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{}", PERMISSION_VALUE_ERROR)
    }
}

impl Error for PermissionShiftError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_permission_valid() {
        let perm = Permission::new("TEST_PERMISSION".to_string(), 0);

        assert_eq!(perm.name, "TEST_PERMISSION".to_string());
        assert_eq!(perm.value, 1 << 0);
    }

    #[test]
    #[should_panic]
    fn test_panic_exceeded_max_shift() {
        let _ = Permission::new("TEST_PERMISSION".to_string(), 35);
    }

    #[test]
    fn test_panic_invalid_value_not_power_of_two() {
        // value that is not 0, 1, or a power of 2
        let invalid_value: u64 = (1 << 26) + 17; // 67108881
        let ret = validate_value(&invalid_value);

        assert!(ret.is_err())
    }

    #[test]
    fn test_panic_invalid_value_zero() {
        // value of zero should fail
        let invalid_value: u64 = 0;
        let ret = validate_value(&invalid_value);

        assert!(ret.is_err())
    }

    #[test]
    fn test_panic_valid_value_one() {
        // value that is not 0, 1, or a power of 2
        let valid_value: u64 = 1;
        let ret = validate_value(&valid_value);

        assert!(ret.is_ok())
    }
}
