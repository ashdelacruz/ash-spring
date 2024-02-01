package com.ashdelacruz.spring.repository;

import java.util.Optional;

import org.springframework.data.mongodb.repository.MongoRepository;

import com.ashdelacruz.spring.models.enums.ERole;
import com.ashdelacruz.spring.models.enums.EToken;
import com.ashdelacruz.spring.models.mongodb.collections.Role;
import com.ashdelacruz.spring.models.mongodb.collections.TokenType;

public interface TokenTypeRepository extends MongoRepository<TokenType, String> {
    Optional<TokenType> findByName(EToken name);

    Boolean existsByName(EToken name);

    Optional<TokenType> findById(int id);

    Boolean existsById(int id);
}