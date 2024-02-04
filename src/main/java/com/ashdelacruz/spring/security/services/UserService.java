package com.ashdelacruz.spring.security.services;

import java.util.Date;
import java.util.Optional;
import java.util.UUID;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.ashdelacruz.spring.models.email.AuthEmail;
import com.ashdelacruz.spring.models.enums.EToken;
import com.ashdelacruz.spring.models.mongodb.collections.Token;
import com.ashdelacruz.spring.models.mongodb.collections.TokenType;
import com.ashdelacruz.spring.models.mongodb.collections.User;
import com.ashdelacruz.spring.repository.TokenRepository;
import com.ashdelacruz.spring.repository.TokenTypeRepository;
import com.ashdelacruz.spring.repository.UserRepository;
import com.ashdelacruz.spring.services.EmailService;

import lombok.extern.slf4j.Slf4j;

@Service
@Transactional
@Slf4j
public class UserService {

    @Value("${lockTimeDurationMs}")
    private int lockTimeDurationMs;

    @Value("${loginUrl}")
    private String loginUrl;

    
    @Autowired
    private UserRepository userRepository;

    @Autowired
    EmailService emailService;

    @Autowired
    TokenRepository tokenRepository;

    @Autowired
    TokenTypeRepository tokenTypeRepository;

    public User getById(String id) {
        return userRepository.findById(id).orElseThrow();
    }

    public User getByUsername(String username) {
        if (userRepository.existsByUsername(username)) {
            return userRepository.findByUsername(username).get();
        }
        return null;
    }

    public User getByEmail(String email) {
        return userRepository.findByEmail(email).orElseThrow();
    }

    public void increaseFailedAttempts(User user) {
        int newFailAttempts = user.getFailedLoginAttempts() + 1;
        user.setFailedLoginAttempts(newFailAttempts);
        userRepository.save(user);
    }

    public void resetFailedAttempts(User user) {
        user.setFailedLoginAttempts(0);
        userRepository.save(user);
    }

    public void lock(User user) {
        user.setAccountNonLocked(false);
        user.setLockTime(new Date(System.currentTimeMillis()));
        userRepository.save(user);
    }

    public void unlock(User user) {
        user.setAccountNonLocked(true);
        user.setLockTime(null);
        userRepository.save(user);
    }

    public boolean unlockWhenTimeExpired(User user) {
        long lockTimeInMillis = user.getLockTime().getTime();
        long currentTimeInMillis = System.currentTimeMillis();

        if (lockTimeInMillis + this.lockTimeDurationMs < currentTimeInMillis) {
            user.setAccountNonLocked(true);
            user.setLockTime(null);
            user.setFailedLoginAttempts(0);

            userRepository.save(user);

            return true;
        }

        return false;
    }

    public void sendAccountActivationLink(User user) {
        String url = this.loginUrl;
        String tokenExpirationDate;
        TokenType tokenType = tokenTypeRepository.findByName(EToken.LOGIN).get();
        if (tokenRepository.existsByUser(user)) {
            log.info("existing token found, use for account activation");

            Token existingToken = tokenRepository.findByUser(user).get();

            if (!existingToken.getType().getId().equals(tokenType.getId())) {

                log.info("existing token was not a " + tokenType.getName() + " token; converting to "
                        + tokenType.getName() + " token and saving");
                existingToken.setType(tokenType);
                tokenRepository.save(existingToken);

            }

            tokenExpirationDate = existingToken.getExpirationDate().toString();

            url += "?token=" + existingToken.getToken();
            log.info("account activation link = {}, expiration = {}",
                    url, tokenExpirationDate);

        } else {
            log.info("creating new token for account activation");

            String tokenString = UUID.randomUUID().toString();
            Token newToken = new Token(user, tokenString, tokenType);
            tokenRepository.save(newToken);
            tokenExpirationDate = newToken.getExpirationDate().toString();

            url += "?token=" + newToken.getToken();
            log.info("account activation link = {}, expiration = {}",
                    url, tokenExpirationDate);
        }

        AuthEmail authEmail = new AuthEmail(
                user.getEmail(),
                user.getUsername(),
                "Welcome to AshDelaCruz.com!",
                "Your account request has been approved. To activate your account, please login via the link below.",
                url,
                "The above link will expire on " + tokenExpirationDate + ".");

        emailService.htmlAuthSend(authEmail);
        log.info("account activation email sent to {}", user.getEmail());

    }



    public void updateDatabaseUserAuth(String userID, boolean isAccountActivationSuccess) {
        // At this point, the user must exist
        User databaseUser = userRepository.findById(userID).get();
        log.info("found user {} from userDetails {}", databaseUser.getId(), userID);

        databaseUser.setLastLogin(new Date(System.currentTimeMillis()));
        databaseUser.setFailedLoginAttempts(0);
        log.info("updating lastLogin for user");

        if (isAccountActivationSuccess) {
            log.info("user account activation successful; updating databaseUser status to active");
            databaseUser.setEnabled(true);
        }

        userRepository.save(databaseUser);
        log.info("databaseUser saved");
    }


  
}
