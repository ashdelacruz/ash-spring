package com.ashdelacruz.spring.security.services;

import java.util.Calendar;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import com.ashdelacruz.spring.models.enums.EToken;
import com.ashdelacruz.spring.models.mongodb.collections.Token;
import com.ashdelacruz.spring.models.mongodb.collections.TokenType;
import com.ashdelacruz.spring.models.mongodb.collections.User;
import com.ashdelacruz.spring.repository.TokenRepository;
import com.ashdelacruz.spring.repository.TokenTypeRepository;
import com.ashdelacruz.spring.repository.UserRepository;

import lombok.extern.slf4j.Slf4j;

@Service
@Slf4j
public class TokenService {

    @Autowired
    TokenRepository tokenRepository;

    @Autowired
    TokenTypeRepository tokenTypeRepository;

    @Autowired
    UserRepository userRepository;

    public boolean isTokenFound(String token) {
        return tokenRepository.existsByToken(token);
    }

    public boolean isTokenExpired(String token) {
        Token foundToken = tokenRepository.findByToken(token).orElseThrow(() -> new RuntimeException("Error: Token " + token + " not found"));
        final Calendar cal = Calendar.getInstance();
        return foundToken.getExpirationDate().before(cal.getTime());
    }

    public boolean isTokenCorrectType(String token, EToken type) {
        Token foundToken = tokenRepository.findByToken(token).orElseThrow(() -> new RuntimeException("Error: Token " + token + " not found"));
        TokenType tokenType = tokenTypeRepository.findByName(type).get();
                               
        return foundToken.getType() == tokenType;
    }

    public void deleteUsedToken(String token) {
           final Token passToken = tokenRepository.findByToken(token)
                .orElseThrow(() -> new RuntimeException("Error: Password token not found"));

                tokenRepository.delete(passToken);
    }

    public User getUserByToken(String token) {
        final Token foundToken = tokenRepository.findByToken(token).get();
        final User user = userRepository.findById(foundToken.getUser().getId()).get();

        return user;

    }
    






}
