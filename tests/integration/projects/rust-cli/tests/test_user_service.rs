//! Integration tests for user service module.

use rust_cli::user_service::UserService;

#[test]
fn test_add_user() {
    let mut service = UserService::new();
    service.add_user("user1", "John Doe");
    assert!(service.user_exists("user1"));
}

#[test]
fn test_user_count() {
    let mut service = UserService::new();
    assert_eq!(service.get_user_count(), 0);
    service.add_user("user1", "John");
    assert_eq!(service.get_user_count(), 1);
}

#[test]
fn test_clear_users() {
    let mut service = UserService::new();
    service.add_user("user1", "John");
    service.add_user("user2", "Jane");
    service.clear_users();
    assert_eq!(service.get_user_count(), 0);
}

#[test]
fn test_user_not_exists() {
    let service = UserService::new();
    assert!(!service.user_exists("nonexistent"));
}

#[test]
fn test_get_user() {
    let mut service = UserService::new();
    service.add_user("user1", "Alice");
    assert_eq!(service.get_user("user1"), Some("Alice".to_string()));
}

#[test]
fn test_get_nonexistent_user() {
    let service = UserService::new();
    assert_eq!(service.get_user("missing"), None);
}
