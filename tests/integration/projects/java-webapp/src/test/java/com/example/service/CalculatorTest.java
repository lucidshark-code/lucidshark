package com.example.service;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.DisplayName;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Tests for Calculator service.
 */
class CalculatorTest {

    private Calculator calculator;

    @BeforeEach
    void setUp() {
        calculator = new Calculator();
    }

    @Test
    @DisplayName("Add two positive numbers")
    void testAdd() {
        assertEquals(5, calculator.add(2, 3));
    }

    @Test
    @DisplayName("Add negative numbers")
    void testAddNegative() {
        assertEquals(-5, calculator.add(-2, -3));
    }

    @Test
    @DisplayName("Subtract two numbers")
    void testSubtract() {
        assertEquals(2, calculator.subtract(5, 3));
    }

    @Test
    @DisplayName("Multiply two numbers")
    void testMultiply() {
        assertEquals(6, calculator.multiply(2, 3));
    }

    @Test
    @DisplayName("Divide two numbers")
    void testDivide() {
        assertEquals(2, calculator.divide(6, 3));
    }

    @Test
    @DisplayName("Division by zero throws exception")
    void testDivideByZero() {
        assertThrows(ArithmeticException.class, () -> calculator.divide(1, 0));
    }
}
