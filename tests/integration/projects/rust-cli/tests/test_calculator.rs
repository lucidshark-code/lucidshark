//! Integration tests for calculator module.

use rust_cli::calculator;

#[test]
fn test_add() {
    assert_eq!(calculator::add(2, 3), 5);
}

#[test]
fn test_add_negative() {
    assert_eq!(calculator::add(-2, -3), -5);
}

#[test]
fn test_subtract() {
    assert_eq!(calculator::subtract(5, 3), 2);
}

#[test]
fn test_multiply() {
    assert_eq!(calculator::multiply(2, 3), 6);
}

#[test]
fn test_divide() {
    assert_eq!(calculator::divide(6, 3), Ok(2));
}

#[test]
fn test_divide_by_zero() {
    assert!(calculator::divide(1, 0).is_err());
}
