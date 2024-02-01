package com.ashdelacruz.spring.repository;
import java.util.Optional;

import org.springframework.data.mongodb.repository.MongoRepository;

import com.ashdelacruz.spring.models.mongodb.collections.Token;
import com.ashdelacruz.spring.models.mongodb.collections.User;


public interface TokenRepository extends MongoRepository<Token, String>{
     Optional<Token> findById(String id);

     Optional<Token> findByToken(String token);

     Optional<Token> findByUser(User user);

     Boolean existsByUser(User user);

     Boolean existsByToken(String token);
}
