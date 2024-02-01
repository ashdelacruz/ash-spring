package com.ashdelacruz.spring.repository;

import java.util.Optional;

import org.springframework.data.mongodb.repository.MongoRepository;

import com.ashdelacruz.spring.models.mongodb.collections.User;


public interface UserRepository extends MongoRepository<User, String> {
    Optional<User> findByUsername(String username);

    Optional<User> findByEmail(String email);

    Boolean existsByUsername(String username);

    Boolean existsByEmail(String email);
}