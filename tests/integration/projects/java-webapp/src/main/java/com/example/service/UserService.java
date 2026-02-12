package com.example.service;

import java.util.HashMap;
import java.util.Map;

/**
 * User service with intentional bugs for SpotBugs testing.
 */
public class UserService {

    private Map<String, String> users = new HashMap<>();

    /**
     * Gets a user by ID.
     *
     * @param userId the user ID
     * @return the user name or null if not found
     */
    public String getUser(String userId) {
        // Potential null dereference - SpotBugs should catch this
        return users.get(userId).toUpperCase();
    }

    /**
     * Adds a user.
     *
     * @param userId user ID
     * @param name user name
     */
    public void addUser(String userId, String name) {
        users.put(userId, name);
    }

    /**
     * Checks if user exists.
     *
     * @param userId user ID
     * @return true if user exists
     */
    public boolean userExists(String userId) {
        // Inefficient - could use containsKey
        return users.get(userId) != null;
    }

    /**
     * Gets user count.
     *
     * @return number of users
     */
    public int getUserCount() {
        return users.size();
    }

    /**
     * Clears all users.
     */
    public void clearUsers() {
        users.clear();
    }
}
