package com.ashdelacruz.spring.security.eventListeners;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.ApplicationListener;
import org.springframework.lang.NonNull;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.authentication.event.AuthenticationFailureDisabledEvent;
import org.springframework.stereotype.Component;

import com.ashdelacruz.spring.models.mongodb.collections.User;
import com.ashdelacruz.spring.security.services.UserService;

import lombok.extern.slf4j.Slf4j;

@Component
@Slf4j
public class DisabledEventListener implements
        ApplicationListener<AuthenticationFailureDisabledEvent> {

    @Autowired
    private UserService userService;

    @Override
    public void onApplicationEvent(@NonNull AuthenticationFailureDisabledEvent e) {

        User user = userService.getByUsername(e.getAuthentication().getPrincipal().toString());

        if (user != null) {
             if (user.getRoles().isEmpty()) {
                log.info("user is pending approval");
                throw new DisabledException(
                        "Your account is pending approval. You will receive an email when your account request has been approved.");
            }

            if (!user.getRoles().isEmpty() && user.getLastLogin() == null) {
                log.info("user is approved, but pending account activation");
                this.userService.sendAccountActivationLink(user);
                throw new DisabledException(
                        "Your account has been approved. To activate your account, please login via the link in your email.");
            }
        }
    }
}