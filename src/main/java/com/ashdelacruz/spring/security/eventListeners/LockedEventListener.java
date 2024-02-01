package com.ashdelacruz.spring.security.eventListeners;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.ApplicationListener;
import org.springframework.lang.NonNull;
import org.springframework.security.authentication.LockedException;
import org.springframework.security.authentication.event.AuthenticationFailureLockedEvent;
import org.springframework.stereotype.Component;

import com.ashdelacruz.spring.models.mongodb.collections.User;
import com.ashdelacruz.spring.security.services.UserService;

import lombok.extern.slf4j.Slf4j;

@Component
@Slf4j
public class LockedEventListener implements
        ApplicationListener<AuthenticationFailureLockedEvent> {

    @Autowired
    private UserService userService;

    /**
     * If the user's account lock has NOT expired, then return normal Lock Exception response
     * Else unlock the user and return Lock response informing user to login again
     *
     */
    @Override
    public void onApplicationEvent(@NonNull AuthenticationFailureLockedEvent e) {

        User user = userService.getByUsername(e.getAuthentication().getPrincipal().toString());

        if(user != null) {
            if (!user.isAccountNonLocked()) {
                log.info("user is locked");
                if (userService.unlockWhenTimeExpired(user)) {
                    log.info("locktime has expired, user unlocked");
                    throw new LockedException("Your account has been unlocked. Please try to login again.");
                }
            }
        }

    }
}