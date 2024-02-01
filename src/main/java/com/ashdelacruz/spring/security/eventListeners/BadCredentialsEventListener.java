package com.ashdelacruz.spring.security.eventListeners;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.ApplicationListener;
import org.springframework.lang.NonNull;
import org.springframework.security.authentication.LockedException;
import org.springframework.security.authentication.event.AuthenticationFailureBadCredentialsEvent;
import org.springframework.stereotype.Component;

import com.ashdelacruz.spring.models.mongodb.collections.User;
import com.ashdelacruz.spring.security.services.UserService;
import com.ashdelacruz.spring.services.EmailService;

import lombok.extern.slf4j.Slf4j;

@Component
@Slf4j
public class BadCredentialsEventListener implements
        ApplicationListener<AuthenticationFailureBadCredentialsEvent> {

    @Autowired
    private UserService userService;


    @Autowired
    private EmailService emailService;

    @Value("${maxFailedLoginAttempts}")
    private int maxFailedLoginAttempts;

    @Override
    public void onApplicationEvent (@NonNull AuthenticationFailureBadCredentialsEvent e) {

        User user = userService.getByUsername(e.getAuthentication().getPrincipal().toString());

        if (user != null) {
            if (user.isAccountNonLocked()) {
                if (user.getFailedLoginAttempts() <= this.maxFailedLoginAttempts) {
                    log.info("not locked yet, increating FailedLoginAttempts");
                    userService.increaseFailedAttempts(user);
                } else {
                    log.info("Locking user");
                    userService.lock(user);
                    emailService.sendAccountLockedEmail(user);
                    throw new LockedException(
                            "User account has been locked for 24 hours, due too many failed attempts.");

                }
            }
        }
    }
}