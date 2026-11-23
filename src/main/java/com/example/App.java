package com.example;

public class App {

    public static void main(String[] args) {
        System.out.println(greeting("world"));
    }

    static String greeting(String name) {
        return "Hello, " + name;
    }
}