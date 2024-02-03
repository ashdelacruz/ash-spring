package com.ashdelacruz.spring.security.services;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import com.ashdelacruz.spring.models.UserDetailsImpl;
import com.ashdelacruz.spring.models.email.AuthEmail;
import com.ashdelacruz.spring.models.email.NotificationEmail;
import com.ashdelacruz.spring.models.enums.ERole;
import com.ashdelacruz.spring.models.enums.EToken;
import com.ashdelacruz.spring.models.mongodb.collections.Role;
import com.ashdelacruz.spring.models.mongodb.collections.Token;
import com.ashdelacruz.spring.models.mongodb.collections.TokenType;
import com.ashdelacruz.spring.models.mongodb.collections.User;
import com.ashdelacruz.spring.repository.RoleRepository;
import com.ashdelacruz.spring.repository.TokenRepository;
import com.ashdelacruz.spring.repository.TokenTypeRepository;
import com.ashdelacruz.spring.repository.UserRepository;
import com.ashdelacruz.spring.security.jwt.JwtUtils;
import com.ashdelacruz.spring.services.EmailService;

import lombok.extern.slf4j.Slf4j;

@Service
@Slf4j
public class UserModService {

    @Autowired
    UserRepository userRepository;

    @Autowired
    RoleRepository roleRepository;

    @Autowired
    PasswordEncoder encoder;

    @Autowired
    TokenService tokenService;

    @Autowired
    ResponseService responseService;

    @Autowired
    JwtUtils jwtUtils;

    @Autowired
    EmailService emailService;

    @Autowired
    TokenRepository tokenRepository;

    @Autowired
    TokenTypeRepository tokenTypeRepository;

    @Autowired
    UserDetailsServiceImpl userDetailsService;

    @Value("${loginUrl}")
    private String loginUrl;

    @Value("${contactUrl}")
    private String contactUrl;

    public ResponseEntity<?> getAllUsers() {
        ResponseEntity<Object> response;

        List<UserDetails> userDetailsList = userDetailsService.loadAllUsers();
        log.info("userDetailsList = {}", Arrays.toString(userDetailsList.toArray()));
        if (userDetailsList == null || userDetailsList.isEmpty()) {
            response = this.responseService.generateResponse("No users found", HttpStatus.NO_CONTENT, null);
            log.warn("RETURN response = {}", response.toString());
            return response;
        }
        log.info("user list is NOT empty");

        Map<String, List<UserDetails>> responseData = new HashMap<String, List<UserDetails>>();
        responseData.put("users", userDetailsList);
        log.info("mapping responseUsers to responseData");

        response = this.responseService.generateResponse("Request Successful", HttpStatus.OK,
                responseData);
        log.info("RETURN response = {}", response.toString());
        return response;
    }

    public ResponseEntity<?> getUserInfo(List<String> ids, List<String> usernames, List<String> emails) {
        ResponseEntity<Object> response;

        List<User> validUsers = new ArrayList<User>();

        if (!ids.isEmpty()) {
            log.info("ds = {}", Arrays.toString(ids.toArray()));
            for (int i = 0; i < ids.size(); i++) {
                if (!userRepository.existsById(ids.get(i))) {

                    response = this.responseService.generateResponse("User ID " + ids.get(i) + " not found.",
                            HttpStatus.UNPROCESSABLE_ENTITY, null);
                    log.error("RETURN response = {}", response.toString());
                    return response;
                }

                User user = userRepository.findById(ids.get(i)).get();
                validUsers.add(user);
            }
        }

        if (!usernames.isEmpty()) {
            log.info("usernames = {}", Arrays.toString(usernames.toArray()));
            for (int i = 0; i < usernames.size(); i++) {
                if (!userRepository.existsByUsername(usernames.get(i))) {

                    response = this.responseService.generateResponse("Username " + usernames.get(i) + " not found.",
                            HttpStatus.UNPROCESSABLE_ENTITY, null);
                    log.error("RETURN response = {}", response.toString());
                    return response;

                }
                User user = userRepository.findByUsername(usernames.get(i)).get();

                // In case user already found by ID
                if (!validUsers.contains(user)) {
                    validUsers.add(user);
                }
            }
        }

        if (!emails.isEmpty()) {
            log.info("emails = {}", Arrays.toString(emails.toArray()));
            for (int i = 0; i < emails.size(); i++) {

                if (!userRepository.existsByEmail(emails.get(i))) {
                    response = this.responseService.generateResponse("Email " + emails.get(i) + " not found.",
                            HttpStatus.UNPROCESSABLE_ENTITY, null);
                    log.error("RETURN response = {}", response.toString());
                    return response;
                }

                User user = userRepository.findByEmail(emails.get(i)).get();

                // In case user already found by ID or username
                if (!validUsers.contains(user)) {
                    validUsers.add(user);
                }

            }
        }

        // Get list of users
        if (validUsers.size() == 0) {
            response = this.responseService.generateResponse("No users found.",
                    HttpStatus.NO_CONTENT, null);
            log.error("RETURN response = {}", response.toString());
            return response;
        }
        log.info("users found for all user info in request");

        // Convert to list of baseUsers to remove passwords
        List<UserDetails> responseUsers = new ArrayList<>(validUsers.size());
        log.info("converting users to responseUsers to remove password");

        for (User user : validUsers) {
            responseUsers.add(UserDetailsImpl.build(user));
        }
        log.info("responseUsers = {}", Arrays.toString(responseUsers.toArray()));

        Map<String, List<UserDetails>> responseData = new HashMap<String, List<UserDetails>>();
        responseData.put("users", responseUsers);
        log.info("mapping responseUsers to responseData");

        response = this.responseService.generateResponse("Request Successful", HttpStatus.OK,
                responseData);
        log.info("RETURN response = {}", response.toString());
        return response;

    }

    // public ResponseEntity<?> contactUsers(ContactRequest contactRequest) {

    // }

    public ResponseEntity<?> resendAccountActivationLink(List<String> ids) {
        ResponseEntity<Object> response;
        List<User> validUsers = new ArrayList<User>();

        log.info("userIDs = {} ", Arrays.toString(validUsers.toArray()));

        // Validate users
        for (int i = 0; i < ids.size(); i++) {
            if (!userRepository.existsById(ids.get(i))) {
                response = this.responseService.generateResponse("User ID " + ids.get(i) + " not found",
                        HttpStatus.UNPROCESSABLE_ENTITY, null);
                log.error("RETURN response = {} ", response.toString());
                return response;
            }
            User user = userRepository.findById(ids.get(i)).get();
            log.info("user found for id {}", ids.get(i));

            if (user.getLastLogin() != null) {
                response = this.responseService.generateResponse(
                        "User ID " + ids.get(i) + " has already activated their account",
                        HttpStatus.UNPROCESSABLE_ENTITY, null);
                log.error("RETURN response = {} ", response.toString());
                return response;

            }

            if (user.getLastLogin() == null && !user.isEnabled()) {
                response = this.responseService.generateResponse(
                        "User ID " + ids.get(i) + " is pending approval",
                        HttpStatus.UNPROCESSABLE_ENTITY, null);
                log.error("RETURN response = {} ", response.toString());
                return response;
            }

            log.info("user is valid; adding to validUsers");
            validUsers.add(user);
        }

        log.info("all userIDs valid = {}", Arrays.toString(validUsers.toArray()));

        List<UserDetails> responseUsers = new ArrayList<>(validUsers.size());
        for (User user : validUsers) {
            // If a token already exists for the user e.g. for password reset,
            // Then repurpose token for login. Previous links will be invalidated

            String tokenString;
            Date tokenExpirationDate;
            TokenType tokenType = tokenTypeRepository.findByName(EToken.LOGIN).get();
            if (tokenRepository.existsByUser(user)) {
                Token existingToken = tokenRepository.findByUser(user).get();
                if (existingToken.getType() != tokenType) {
                    existingToken.setType(tokenType);
                }
                tokenString = existingToken.getToken();
                tokenExpirationDate = existingToken.getExpirationDate();
                tokenRepository.save(existingToken);
            } else {
                // Create new token
                tokenString = UUID.randomUUID().toString();
                Token loginToken = new Token(user, tokenString, tokenType);
                tokenExpirationDate = loginToken.getExpirationDate();
                tokenRepository.save(loginToken);
                log.info("generated account activation token");
            }

            // Send reset creds link to email
            String url = this.loginUrl + "?token=" + tokenString;
            log.info("generated account activation link");

            AuthEmail authEmail = new AuthEmail(
                    user.getEmail(),
                    user.getUsername(),
                    "Welcome to AshDelaCruz.com!",
                    "Your account request has been approved. To activate your account, please login via the link below.",
                    url,
                    "The above link will expire on " + tokenExpirationDate + ".");
            emailService.htmlAuthSend(authEmail);
            log.info("account activation email sent to user {}", user.getUsername());

            userRepository.save(user);
            log.info("user saved; adding to responseUsers");
            responseUsers.add(UserDetailsImpl.build(user));
        }

        Map<String, List<UserDetails>> responseData = new HashMap<String, List<UserDetails>>();
        responseData.put("users", responseUsers);
        log.info("mapping responseUsers to responseData");

        response = this.responseService.generateResponse(
                "Successfully resent account activation email for user(s)", HttpStatus.OK,
                responseData);
        log.info("RETURN response = {}", response.toString());
        return response;

    }

    public ResponseEntity<?> setRole(List<String> ids, ERole newRole) {
        ResponseEntity<Object> response;
        List<User> validUsers = new ArrayList<User>();

        log.info("userIDs = {}", Arrays.toString(validUsers.toArray()));
        log.info("newRole = {}", newRole);

        if (!roleRepository.existsByName(newRole)) {
            response = this.responseService.generateResponse("newRole \"" + newRole + "\" is invalid",
                    HttpStatus.UNPROCESSABLE_ENTITY, null);
            log.error("RETURN response = {} ", response.toString());
            return response;
        }
        log.info("newRole is valid");

        Role role = roleRepository.findByName(newRole).get();
        log.info("role to set = {}", role.toString());

        // Validate users
        for (int i = 0; i < ids.size(); i++) {
            if (!userRepository.existsById(ids.get(i))) {
                response = this.responseService.generateResponse("User ID " + ids.get(i) + " not found",
                        HttpStatus.UNPROCESSABLE_ENTITY, null);
                log.error("RETURN response = {}", response.toString());
                return response;

            }
            log.info("user ID {} exists", ids.get(i));

            User databaseUser = userRepository.findById(ids.get(i)).get();
            log.info("databaseUser found; username = {}", databaseUser.getUsername());

            // validUsers.add(databaseUser);
            // log.info("added databaseUser to validUsers = {}",
            // Arrays.toString(validUsers.toArray()));

            /**
             * Removed checking if user is already new role,
             * as this implementation is broken but that use case is prevented by frontend
             * anyways
             * 
             * It's still possible to set the user role to the
             * current role through Postman, but that's not a problem
             */

            // log.info("is user already newRole? {}",
            // databaseUser.getRoles().contains(role));

            // // Check users are not already newRole
            // if (databaseUser.getRoles().contains(role)) {
            // response = this.responseService.generateResponse(
            // "User " + ids.get(i) + " is already " + role.toString(),
            // HttpStatus.UNPROCESSABLE_ENTITY, null);
            // log.error("RETURN response = {}",
            // response.toString());
            // return response;
            // }

            validUsers.add(databaseUser);
            log.info("User {} is NOT already {}; Added user to validUsers = {}",
                    databaseUser.getUsername(),
                    role.toString(),
                    Arrays.toString(validUsers.toArray()));

        }

        log.info("all userIDs exist; validUsers = {}", Arrays.toString(validUsers.toArray()));

        // Set the roles
        List<UserDetails> responseUsers = new ArrayList<>(validUsers.size());
        for (User user : validUsers) {
            Set<Role> userRoles = new HashSet<>();

            if (newRole == ERole.ROLE_ADMIN) {

                userRoles.add(roleRepository.findByName(ERole.ROLE_ADMIN).get());
                userRoles.add(roleRepository.findByName(ERole.ROLE_MODERATOR).get());
                userRoles.add(roleRepository.findByName(ERole.ROLE_USER).get());
                userRoles.add(roleRepository.findByName(ERole.ROLE_GUEST).get());
                user.setRoles(userRoles);
                log.info("update user with ADMIN role = {}", user.getRoles().toArray().toString());

            } else if (newRole == ERole.ROLE_MODERATOR) {

                userRoles.add(roleRepository.findByName(ERole.ROLE_MODERATOR).get());
                userRoles.add(roleRepository.findByName(ERole.ROLE_USER).get());
                userRoles.add(roleRepository.findByName(ERole.ROLE_GUEST).get());
                user.setRoles(userRoles);
                log.info("update user with MODERATOR role = {}", user.getRoles().toArray().toString());

            } else if (newRole == ERole.ROLE_USER) {

                userRoles.add(roleRepository.findByName(ERole.ROLE_USER).get());
                userRoles.add(roleRepository.findByName(ERole.ROLE_GUEST).get());
                user.setRoles(userRoles);
                log.info("update user with USER role = {}", user.getRoles().toArray().toString());

            } else if (newRole == ERole.ROLE_GUEST) {

                userRoles.add(roleRepository.findByName(ERole.ROLE_GUEST).get());
                user.setRoles(userRoles);
                log.info("update user with GUEST role = {}", user.getRoles().toArray().toString());

            } else {
                log.error("Invalid Role = {}", newRole);
            }

            // If assigning a role to a user with status -1
            // then must be approving a user account request,
            // so generate an account activation link and send to email
            if (user.getLastLogin() == null) {
                user.setEnabled(true);

                String tokenString;
                String tokenExpirationDate;
                TokenType tokenType = tokenTypeRepository.findByName(EToken.LOGIN).get();
                // If a token already exists for the user e.g. for password reset,
                // Then repurpose for login
                if (tokenRepository.existsByUser(user)) {
                    Token existingToken = tokenRepository.findByUser(user).get();
                    if (existingToken.getType() != tokenType) {
                        existingToken.setType(tokenType);
                    }
                    tokenString = existingToken.getToken();
                    tokenExpirationDate = existingToken.getExpirationDate().toString();
                    tokenRepository.save(existingToken);
                } else {

                    // Create new token
                    tokenString = UUID.randomUUID().toString();
                    Token newToken = new Token(user, tokenString, tokenType);

                    tokenExpirationDate = newToken.getExpirationDate().toString();
                    tokenRepository.save(newToken);
                    log.info("generated account activation token");
                }

                // Send reset creds link to email
                String url = this.loginUrl + "?token=" + tokenString;
                log.info("generated account activation link");

                AuthEmail authEmail = new AuthEmail(
                        user.getEmail(),
                        user.getUsername(),
                        "Welcome to AshDelaCruz.com!",
                        "Your account request has been approved, as a " + newRole
                                + ". To activate your account, please login via the link below.",
                        url,
                        "The above link will expire on " + tokenExpirationDate + ".");
                emailService.htmlAuthSend(authEmail);
                log.info("account activation email sent to user {}", user.getUsername());

            } else {

                AuthEmail authEmail = new AuthEmail(
                        user.getEmail(),
                        user.getUsername(),
                        "Account Role Changed - AshDelaCruz.com",
                        "Your account role has been changed to a " + newRole
                                + ". To activate your account, please login via the link below.",
                        this.loginUrl);
                if (newRole == ERole.ROLE_MODERATOR) {
                    authEmail.setMessage2(
                            "You will now have access to the User Mod board in your menu. You can view user info and activate/deactivate users.");
                }

                if (newRole == ERole.ROLE_ADMIN) {
                    authEmail.setMessage2(
                            "You will now have access to the User Mod board in your menu. You can view user info, activate/deactivate users,  approve/deny pending users, set user roles, and delete users.");
                }
                emailService.htmlAuthSend(authEmail);
                log.info("Role changed notification email sent to user {}", user.getUsername());
            }

            userRepository.save(user);
            log.info("user saved; adding user to responseUsers");
            responseUsers.add(UserDetailsImpl.build(user));

        }

        Map<String, List<UserDetails>> responseData = new HashMap<String, List<UserDetails>>();
        responseData.put("users", responseUsers);
        log.info("mapping responseUsers to responseData");

        response = this.responseService.generateResponse("Successfully set role for user(s)", HttpStatus.OK,
                responseData);
        log.info("RETURN response = {}", response.toString());
        return response;

    }

    public ResponseEntity<?> setStatus(List<String> ids, boolean newStatus) {
        ResponseEntity<Object> response;
        List<User> validUsers = new ArrayList<User>();

        log.info("userIDs = {} ", Arrays.toString(validUsers.toArray()));
        log.info("newStatus = {}", newStatus);

        // Validate user
        for (int i = 0; i < ids.size(); i++) {
            if (!userRepository.existsById(ids.get(i))) {
                response = this.responseService.generateResponse("User ID " + ids.get(i) + " not found",
                        HttpStatus.UNPROCESSABLE_ENTITY, null);
                log.error("RETURN response = {} ", response.toString());
                return response;
            }
            User user = userRepository.findById(ids.get(i)).get();

            if (user.getLastLogin() == null && user.getRoles().isEmpty()) {
                response = this.responseService.generateResponse(
                        "User ID " + ids.get(i) + " is pending approval",
                        HttpStatus.UNPROCESSABLE_ENTITY, null);
                log.error("RETURN response = {} ", response.toString());
                return response;
            }

            if (user.getLastLogin() == null && !user.getRoles().isEmpty()) {
                response = this.responseService.generateResponse(
                        "User ID " + ids.get(i) + " requires account activation",
                        HttpStatus.UNPROCESSABLE_ENTITY, null);
                log.error("RETURN response = {} ", response.toString());
                return response;

            }

            if (user.isEnabled() == newStatus) {
                response = this.responseService.generateResponse(
                        "User ID " + ids.get(i) + " is already " + (newStatus ? "enabled" : "disabled"),
                        HttpStatus.UNPROCESSABLE_ENTITY, null);
                log.error("RETURN response = {} ", response.toString());
                return response;

            }

            log.info("user is valid; adding to validUsers");
            validUsers.add(user);

        }
        log.info("all userIDs valid = {}", Arrays.toString(validUsers.toArray()));

        List<UserDetails> responseUsers = new ArrayList<>(validUsers.size());
        for (User user : validUsers) {
            user.setEnabled(newStatus);
            log.info("updating user status");

            AuthEmail authEmail = new AuthEmail(
                    user.getEmail(),
                    user.getUsername(),
                    ("Account " + (newStatus ? " Activated" : " Deactivated") + " - AshDelaCruz.com"),
                    "Your account has been "
                            + (newStatus ? " activated by a moderator."
                                    : " deactivated by a moderator."));

            if (!newStatus) {
                log.info("add contact URL for deactivated user");
                authEmail.setUrl(this.contactUrl);
                authEmail.setMessage2("If you have any questions, please click the link above.");
            }

            if (newStatus && user.getFailedLoginAttempts() >= 3) {
                // If activating user that was locked due to too many failed passwordAttempts,
                // Then reset passwordAttempts to 0
                user.setFailedLoginAttempts(0);
            }
            emailService.htmlAuthSend(authEmail);
            log.info("Status change notification email sent to user {}", user.getUsername());

            userRepository.save(user);
            log.info("user saved; adding to responseUsers");
            responseUsers.add(UserDetailsImpl.build(user));
        }

        Map<String, List<UserDetails>> responseData = new HashMap<String, List<UserDetails>>();
        responseData.put("users", responseUsers);
        log.info("mapping responseUsers to responseData");

        response = this.responseService.generateResponse(
                "Successfully" + (newStatus ? " enabled" : " disabled") + " user(s)", HttpStatus.OK,
                responseData);
        log.info("RETURN response = {}", response.toString());
        return response;

    }

    public ResponseEntity<?> unlock(List<String> ids) {
        ResponseEntity<Object> response;
        List<User> validUsers = new ArrayList<User>();

        log.info("userIDs = {} ", Arrays.toString(validUsers.toArray()));

        // Validate user
        for (int i = 0; i < ids.size(); i++) {
            if (!userRepository.existsById(ids.get(i))) {
                response = this.responseService.generateResponse("User ID " + ids.get(i) + " not found",
                        HttpStatus.UNPROCESSABLE_ENTITY, null);
                log.error("RETURN response = {} ", response.toString());
                return response;
            }
            User user = userRepository.findById(ids.get(i)).get();

            if (user.getLastLogin() == null && user.getRoles().isEmpty()) {
                response = this.responseService.generateResponse(
                        "User ID " + ids.get(i) + " is pending approval",
                        HttpStatus.UNPROCESSABLE_ENTITY, null);
                log.error("RETURN response = {} ", response.toString());
                return response;
            }

            if (user.isAccountNonLocked()) {
                response = this.responseService.generateResponse(
                        "User ID " + ids.get(i) + " is already unlocked",
                        HttpStatus.UNPROCESSABLE_ENTITY, null);
                log.error("RETURN response = {} ", response.toString());
                return response;

            }

            log.info("user is valid; adding to validUsers");
            validUsers.add(user);

        }
        log.info("all userIDs valid = {}", Arrays.toString(validUsers.toArray()));

        List<UserDetails> responseUsers = new ArrayList<>(validUsers.size());
        for (User user : validUsers) {
            user.setAccountNonLocked(true);
            user.setLockTime(null);
            user.setFailedLoginAttempts(0);
            log.info("unlocking user");

            this.emailService.sendAccountUnlockedEmail(user);
            log.info("Unlock account notification email sent to user {}", user.getUsername());

            userRepository.save(user);
            log.info("user saved; adding to responseUsers");
            responseUsers.add(UserDetailsImpl.build(user));
        }

        Map<String, List<UserDetails>> responseData = new HashMap<String, List<UserDetails>>();
        responseData.put("users", responseUsers);
        log.info("mapping responseUsers to responseData");

        response = this.responseService.generateResponse(
                "Successfully unlocked user(s)", HttpStatus.OK,
                responseData);
        log.info("RETURN response = {}", response.toString());
        return response;

    }

    public ResponseEntity<?> deleteUser(List<String> ids) {
        ResponseEntity<Object> response;
        List<User> validUsers = new ArrayList<User>();

        log.info("userIDs = {} ", Arrays.toString(validUsers.toArray()));

        // Validate user
        for (int i = 0; i < ids.size(); i++) {
            if (!userRepository.existsById(ids.get(i))) {
                response = this.responseService.generateResponse("User ID " + ids.get(i) + " not found",
                        HttpStatus.UNPROCESSABLE_ENTITY,
                        null);
                log.error("RETURN response = {} ", response.toString());
                return response;
            } else {
                log.info("user exists; adding to validUsers");
                validUsers.add(userRepository.findById(ids.get(i)).get());
            }
        }
        log.info("all userIDs found = {}", Arrays.toString(validUsers.toArray()));

        // Delete the users
        for (User user : validUsers) {
            userRepository.delete(user);
            log.info("deleting user");

            NotificationEmail notificationEmail = new NotificationEmail(
                    user.getEmail(),
                    user.getUsername());

            if (user.getLastLogin() == null) {
                if (!user.isEnabled()) {
                    log.info("user account request denied");
                    notificationEmail.setSubject("Account Request Denied - AshDelaCruz.com");
                    notificationEmail.setMessage1("Your account request has been denied.");

                } else {

                    log.info("user was pending account activation");
                    notificationEmail.setSubject("Account Deleted - AshDelaCruz.com");
                    notificationEmail.setMessage1(
                            "Your account has been deleted by a moderator. Your account activation link has been invalidated.");
                }
            } else {
                notificationEmail.setSubject("Account Deleted - AshDelaCruz.com");
                notificationEmail.setMessage1("Your account has been deleted by a moderator");
            }

            emailService.htmlNotificationSend(notificationEmail);
            log.info("account deleted/denied email sent to {}", user.getEmail());
        }

        response = this.responseService.generateResponse("Sucessfully deleted user(s)", HttpStatus.ACCEPTED, null);
        log.info("response = {}", response.toString());
        return response;
    }
}
