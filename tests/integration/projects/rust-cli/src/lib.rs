//! Sample library for LucidShark integration tests.
//!
//! Contains intentional clippy warnings and style issues for testing.

pub mod calculator {
    /// Adds two numbers.
    pub fn add(a: i32, b: i32) -> i32 {
        a + b
    }

    /// Subtracts two numbers.
    pub fn subtract(a: i32, b: i32) -> i32 {
        a - b
    }

    /// Multiplies two numbers.
    pub fn multiply(a: i32, b: i32) -> i32 {
        a * b
    }

    /// Divides two numbers.
    pub fn divide(a: i32, b: i32) -> Result<i32, String> {
        if b == 0 {
            Err("Division by zero".to_string())
        } else {
            Ok(a / b)
        }
    }
}

pub mod user_service {
    use std::collections::HashMap;

    /// User service with intentional clippy warnings for testing.
    pub struct UserService {
        users: HashMap<String, String>,
    }

    impl UserService {
        /// Creates a new UserService.
        pub fn new() -> UserService {
            UserService {
                users: HashMap::new(),
            }
        }

        /// Adds a user to the service.
        /// Intentional clippy warning: redundant clone
        pub fn add_user(&mut self, id: &str, name: &str) {
            let name_owned = name.to_string().clone(); // clippy::redundant_clone
            self.users.insert(id.to_string(), name_owned);
        }

        /// Gets a user by ID.
        /// Intentional clippy warning: manual implementation instead of using map
        pub fn get_user(&self, id: &str) -> Option<String> {
            // clippy::manual_map - should use self.users.get(id).map(|v| v.clone())
            match self.users.get(id) {
                Some(name) => Some(name.clone()),
                None => None,
            }
        }

        /// Checks if a user exists.
        pub fn user_exists(&self, id: &str) -> bool {
            self.users.get(id).is_some() // clippy could suggest contains_key
        }

        /// Gets the user count.
        /// Intentional clippy warning: needless return
        pub fn get_user_count(&self) -> usize {
            return self.users.len(); // clippy::needless_return
        }

        /// Clears all users.
        pub fn clear_users(&mut self) {
            self.users.clear();
        }

        /// Unused function parameter for dead_code/clippy warning.
        pub fn format_greeting(&self, id: &str, _prefix: &str) -> String {
            match self.users.get(id) {
                Some(name) => format!("Hello, {}!", name),
                None => "User not found".to_string(),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::calculator;
    use super::user_service::UserService;

    #[test]
    fn test_add() {
        assert_eq!(calculator::add(2, 3), 5);
    }

    #[test]
    fn test_subtract() {
        assert_eq!(calculator::subtract(5, 3), 2);
    }

    #[test]
    fn test_user_service_basic() {
        let mut svc = UserService::new();
        svc.add_user("1", "Alice");
        assert!(svc.user_exists("1"));
        assert_eq!(svc.get_user_count(), 1);
    }
}
