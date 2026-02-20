//! Sample CLI entry point for LucidShark integration tests.

use std::collections::HashMap; // unused import - clippy warning

use rust_cli::calculator;
use rust_cli::user_service::UserService;

fn main() {
    // Calculator demo
    let result = calculator::add(2, 3);
    println!("2 + 3 = {}", result);

    let result = calculator::divide(10, 3);
    match result {
        Ok(val) => println!("10 / 3 = {}", val),
        Err(e) => println!("Error: {}", e),
    }

    // User service demo
    let mut service = UserService::new();
    service.add_user("1", "Alice");
    service.add_user("2", "Bob");

    if service.user_exists("1") {
        println!("User 1 exists: {:?}", service.get_user("1"));
    }

    println!("Total users: {}", service.get_user_count());
}
