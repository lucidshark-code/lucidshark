package com.example.service;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.DisplayName;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Tests for UserService.
 */
class UserServiceTest {

    private UserService userService;

    @BeforeEach
    void setUp() {
        userService = new UserService();
    }

    @Test
    @DisplayName("Add and check user exists")
    void testAddUser() {
        userService.addUser("user1", "John Doe");
        assertTrue(userService.userExists("user1"));
    }

    @Test
    @DisplayName("User count increases after adding")
    void testUserCount() {
        assertEquals(0, userService.getUserCount());
        userService.addUser("user1", "John");
        assertEquals(1, userService.getUserCount());
    }

    @Test
    @DisplayName("Clear users removes all")
    void testClearUsers() {
        userService.addUser("user1", "John");
        userService.addUser("user2", "Jane");
        userService.clearUsers();
        assertEquals(0, userService.getUserCount());
    }

    @Test
    @DisplayName("Non-existent user returns false")
    void testUserNotExists() {
        assertFalse(userService.userExists("nonexistent"));
    }
}
