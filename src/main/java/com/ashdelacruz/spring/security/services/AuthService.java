package com.ashdelacruz.spring.security.services;

import java.util.Date;
import java.util.UUID;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseCookie;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import com.ashdelacruz.spring.models.UserDetailsImpl;
import com.ashdelacruz.spring.models.email.AuthEmail;
import com.ashdelacruz.spring.models.email.NotificationEmail;
import com.ashdelacruz.spring.models.enums.EToken;
import com.ashdelacruz.spring.models.mongodb.collections.Token;
import com.ashdelacruz.spring.models.mongodb.collections.TokenType;
import com.ashdelacruz.spring.models.mongodb.collections.User;
import com.ashdelacruz.spring.payload.request.ContactRequest;
import com.ashdelacruz.spring.payload.request.LoginRequest;
import com.ashdelacruz.spring.payload.request.SignupRequest;
import com.ashdelacruz.spring.payload.request.UpdateRequest;
import com.ashdelacruz.spring.repository.TokenRepository;
import com.ashdelacruz.spring.repository.TokenTypeRepository;
import com.ashdelacruz.spring.repository.UserRepository;
import com.ashdelacruz.spring.security.jwt.JwtUtils;
import com.ashdelacruz.spring.services.EmailService;

import lombok.extern.slf4j.Slf4j;

@Service
@Slf4j
public class AuthService {

        @Autowired
        AuthenticationManager authenticationManager;

        @Autowired
        UserRepository userRepository;

        @Autowired
        TokenRepository tokenRepository;

        @Autowired
        TokenTypeRepository tokenTypeRepository;

        @Autowired
        TokenService tokenService;

        @Autowired
        EmailService emailService;

        @Autowired
        ResponseService responseService;

        @Autowired
        UserService userService;

        @Autowired
        PasswordEncoder encoder;

        @Autowired
        JwtUtils jwtUtils;

        @Value("${myEmail}")
        private String myEmail;

        @Value("${loginUrl}")
        private String loginUrl;

        public final String CONTACT_SUBJECT = "Contact Received From AshDelaCruz.com";
        public final String EXISTING_TOKEN_MESSAGE = " Any links previously sent to your email from AshDelaCruz.com will no longer work.";

        public final String DELETE_ACCOUNT_SUBJECT = "Account Deleted - AshDelaCruz.com";
        public final String DELETE_ACCOUNT_MESSAGE = "Your information has been permanently removed from AshDelaCruz.com.";

        public ResponseEntity<?> createAccountRequest(SignupRequest signUpRequest) {
                log.info("signUpRequest username = {}, email = {}", signUpRequest.getUsername(),
                                signUpRequest.getEmail());

                boolean unameTaken = userRepository.existsByUsername(signUpRequest.getUsername());
                boolean emailTaken = userRepository.existsByEmail(signUpRequest.getEmail());
                log.info("unameTaken = {}, emailTaken = {}", unameTaken, emailTaken);

                ResponseEntity<Object> response;

                // Check existing uname and email
                if (unameTaken && !emailTaken) {
                        log.error("Username " + signUpRequest.getUsername()
                                        + " already in use ");
                        response = this.responseService.generateResponse("Username already in use",
                                        HttpStatus.UNPROCESSABLE_ENTITY,
                                        null);
                        log.error("RETURN response = {}", response.toString());
                        return response;
                } else if (!unameTaken && emailTaken) {
                        response = this.responseService.generateResponse("Email already in use",
                                        HttpStatus.UNPROCESSABLE_ENTITY,
                                        null);
                        log.error("RETURN response = {}", response.toString());
                        return response;
                } else if (unameTaken && emailTaken) {
                        response = this.responseService.generateResponse("Email and Username already in use",
                                        HttpStatus.UNPROCESSABLE_ENTITY,
                                        null);

                        log.error("RETURN response = {}", response.toString());
                        return response;
                }

                User user = new User(signUpRequest.getUsername(),
                                signUpRequest.getEmail(),
                                encoder.encode(signUpRequest.getPassword()));
                log.info("new user created with status = -1 (pending)");

                // Set<Role> pendingRole = new HashSet<>();
                // pendingRole.add(roleRepository.findByName(ERole.ROLE_PENDING).get());
                // user.setRoles(pendingRole);

                userRepository.save(user);
                log.info("new user saved");

                log.info("new user in database = {}", userRepository.findByUsername(user.getUsername()));

                response = this.responseService.generateResponse("Success", HttpStatus.ACCEPTED,
                                "Account requested, pending approval");
                log.info("RETURN response = {}", response.toString());
                return response;

        }

        public ResponseEntity<?> contactFromUser(ContactRequest contactRequest) {
                String message1 = "You have received a message from \"" + contactRequest.getNames()[0] + "\" ("
                                + contactRequest.getEmails()[0] + ")";
                String message2 = "\"" + contactRequest.getMessage() + "\"";
                ResponseEntity<Object> response;

                log.info("email message1 = " + message1);
                log.info("email message2 = " + message2);

                NotificationEmail notificationEmail = new NotificationEmail(
                                this.myEmail,
                                "Ash Dela Cruz",
                                this.CONTACT_SUBJECT,
                                message1,
                                message2);
                emailService.htmlNotificationSend(notificationEmail);
                log.info("contact email sent to receiving email");

                response = this.responseService.generateResponse("Success", HttpStatus.ACCEPTED,
                                "Your message was received, thank you");
                log.info("RETURN response = {}", response.toString());
                return response;

        }

        // public ResponseEntity<?> validateLoginAttempt(String username) {

        // }

        public ResponseEntity<?> authenticateUser(LoginRequest loginRequest,
                        Token token) {

                Authentication authentication = authenticationManager.authenticate(
                                new UsernamePasswordAuthenticationToken(loginRequest.getUsername(),
                                                loginRequest.getPassword()));

                SecurityContextHolder.getContext().setAuthentication(authentication);
                log.info("Authentication set for SecurityContext");
                UserDetailsImpl userDetails = (UserDetailsImpl) authentication.getPrincipal();
                log.info("User authorities = {}", userDetails.getAuthorities().toString());
                ResponseEntity<Object> response;
                boolean isAccountActivationSuccess = false;

                // Valid token found, attempt account activation
                if (token != null) {
                        if (userDetails.getLastLogin() != null) {
                                response = this.responseService.generateResponse(
                                                "User account has already been activated.",
                                                HttpStatus.UNPROCESSABLE_ENTITY, null);
                                log.error("RETURN response = " + response.toString());
                                return response;
                        } else {
                                if (!token.getUser().getId().equals(userDetails.getId())) {
                                        log.warn("Token is valid but for incorrect user {}",
                                                        token.getUser().getUsername());
                                        response = this.responseService.generateResponse("Token invalid",
                                                        HttpStatus.UNPROCESSABLE_ENTITY, null);
                                        log.error("RETURN response = " + response.toString());
                                        return response;

                                } else {
                                        log.info("account activation successful; deleting used token and updating userDetails status to active");
                                        isAccountActivationSuccess = true;
                                        tokenService.deleteUsedToken(token.getToken());
                                }
                        }
                } else {
                        if (userDetails.getLastLogin() == null && userDetails.isEnabled()
                                        && !userDetails.getAuthorities().isEmpty()) {

                                User user = userRepository.findById(userDetails.getId()).get();
                                String tokenString;
                                Date tokenExpirationDate;
                                TokenType tokenType = tokenTypeRepository.findByName(EToken.LOGIN).get();
                                if (tokenRepository.existsByUser(user)) {
                                        Token existingToken = tokenRepository.findByUser(user).get();
                                        if (!existingToken.getType().getId().equals(tokenType.getId())) {
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

                                response = this.responseService.generateResponse(
                                                "User account is pending activation, please login via the link in your email.",
                                                HttpStatus.UNPROCESSABLE_ENTITY, null);
                                log.error("RETURN response = " + response.toString());
                                return response;
                        }
                }

                log.info("user account is active, login as normal");

                ResponseCookie jwtCookie = jwtUtils.generateJwtCookie(userDetails);
                log.info("generated jwt cookie");
                // log.info("jwtCookieString = " + jwtCookie.toString());

                this.userService.updateDatabaseUserAuth(userDetails.getId(), isAccountActivationSuccess);

                return ResponseEntity.ok().header(HttpHeaders.SET_COOKIE, jwtCookie.toString())
                                .body(userDetails);

        }

        public ResponseEntity<?> updateEmail(UpdateRequest updateRequest) {
                ResponseEntity<Object> response;

                if (updateRequest.getNewEmail() == null) {

                        response = this.responseService.generateResponse("New email required",
                                        HttpStatus.BAD_REQUEST, null);
                        log.error("RETURN response = {}", response.toString());
                        return response;

                }
                log.info("newEmail = " + updateRequest.getNewEmail());

                if (userRepository.existsByEmail(updateRequest.getNewEmail())) {
                        response = this.responseService.generateResponse("Email already in use",
                                        HttpStatus.UNPROCESSABLE_ENTITY, null);
                        log.error("RETURN response = {}", response.toString());
                        return response;
                }

                User databaseUser = userRepository.findById(updateRequest.getId()).get();
                log.info("databaseUser found; currentEmail = {}", databaseUser.getEmail());

                databaseUser.setEmail(updateRequest.getNewEmail());
                log.info("updating email for databaseUser; newEmail = {}", databaseUser.getEmail());

                userRepository.save(databaseUser);
                log.info("databaseUser saved");

                log.info("RETURN response = {}", HttpStatus.ACCEPTED);
                return ResponseEntity.accepted().body("\"" + updateRequest.getNewEmail() + "\"");

        }

        public ResponseEntity<?> updateUsername(UpdateRequest updateRequest, UserDetailsImpl loggedInUser) {
                ResponseEntity<Object> response;

                if (updateRequest.getNewUsername() == null) {

                        response = this.responseService.generateResponse("New username required",
                                        HttpStatus.BAD_REQUEST, null);
                        log.error("RETURN response = {}", response.toString());
                        return response;
                }

                log.info("newUsername = " + updateRequest.getNewUsername());

                if (userRepository.existsByUsername(updateRequest.getNewUsername())) {
                        response = this.responseService.generateResponse("Username already in use",
                                        HttpStatus.UNPROCESSABLE_ENTITY, null);
                        log.error("RETURN response = {}", response.toString());
                        return response;
                }

                User databaseUser = userRepository.findById(updateRequest.getId()).get();
                log.info("databaseUser found; currentUsername = {}", databaseUser.getUsername());

                loggedInUser.setUsername(updateRequest.getNewUsername());
                log.info("updating username for loggedInUser; newUsername = {}",
                                loggedInUser.getUsername());
                databaseUser.setUsername(updateRequest.getNewUsername());
                log.info("updating username for databaseUser; newUsername = {}",
                                databaseUser.getUsername());

                userRepository.save(databaseUser);
                log.info("databaseUser saved");

                return authenticateNewUsername(updateRequest, loggedInUser);

        }

        public ResponseEntity<?> authenticateNewUsername(UpdateRequest updateRequest, UserDetailsImpl loggedInUser) {
                Authentication authentication = authenticationManager.authenticate(
                                new UsernamePasswordAuthenticationToken(loggedInUser.getUsername(),
                                                updateRequest.getPassword()));
                log.info("reauthenticating loggedInUser");

                SecurityContextHolder.getContext().setAuthentication(authentication);
                log.info("Authentication set for SecurityContext");

                ResponseCookie jwtCookie = jwtUtils.generateJwtCookie(loggedInUser);
                log.info("generated JWT cookie");
                log.debug("jwtCookieString = {}", jwtCookie.toString());

                log.info("RETURN response = " + HttpStatus.OK);
                return ResponseEntity.ok().header(HttpHeaders.SET_COOKIE, jwtCookie.toString())
                                .body("\"" + updateRequest.getNewUsername() + "\"");
        }

        public ResponseEntity<?> updatePassword(UpdateRequest updateRequest, UserDetailsImpl loggedInUser) {
                ResponseEntity<Object> response;

                if (updateRequest.getNewPassword() == null) {
                        response = this.responseService.generateResponse("New password required",
                                        HttpStatus.BAD_REQUEST, null);
                        log.error("RETURN response = {}", response.toString());
                        return response;
                }
                log.info("newPassword found");

                // log.info("newPassword = "
                // + updateRequest.getNewPassword());

                User databaseUser = userRepository.findById(updateRequest.getId()).get();
                log.info("databaseUser found; currentUsername = {} ", databaseUser.getUsername());

                loggedInUser.setPassword(encoder.encode(updateRequest.getNewPassword()));
                log.info("updating password for loggedInUser");
                databaseUser.setPassword(encoder.encode(updateRequest.getNewPassword()));
                log.info("updating password for databaseUser");

                userRepository.save(databaseUser);
                log.info("databaseUser saved");

                return this.authenticateNewPassword(updateRequest, loggedInUser);

        }

        public ResponseEntity<?> authenticateNewPassword(UpdateRequest updateRequest, UserDetailsImpl loggedInUser) {
                Authentication authentication = authenticationManager.authenticate(
                                new UsernamePasswordAuthenticationToken(loggedInUser.getUsername(),
                                                updateRequest.getNewPassword()));
                log.info("reauthenticating loggedInUser");

                SecurityContextHolder.getContext().setAuthentication(authentication);
                log.info("Authentication set for SecurityContext");

                ResponseCookie jwtCookie = jwtUtils.generateJwtCookie(loggedInUser);
                log.info("generated JWT cookie");
                log.debug("jwtCookieString = {}", jwtCookie.toString());

                log.info("RETURN response = {}", HttpStatus.OK);
                return ResponseEntity.ok().header(HttpHeaders.SET_COOKIE, jwtCookie.toString()).build();
        }

        public void sendResetLink(String email, String message1, String subject, String url, EToken eToken) {
                log.info("tokenType = {}, email = {}, message1 = {}, subject = {}, url = {}",
                                eToken, email,
                                message1, subject, url);

                TokenType tokenType = tokenTypeRepository.findByName(eToken).get();

                if (userRepository.existsByEmail(email)) {
                        log.info("user exists by email");

                        User user = userRepository.findByEmail(email).get();
                        log.info("user found by email; username = {}", user.getUsername());

                        String message2 = "";
                        String tokenExpirationString;
                        boolean isExistingTokenFound = false;

                        if (tokenRepository.existsByUser(user)) {
                                log.info("existing token found; use for reset");

                                isExistingTokenFound = true;
                                Token existingToken = tokenRepository.findByUser(user).get();
                                tokenExpirationString = existingToken.getExpirationDate().toString();
                                // log.debug("existing token = {}", existingToken.toString());

                                if (!existingToken.getType().getId().equals(tokenType.getId())) {
                                        log.info("existing token was a "
                                                        + existingToken.getType().toString() + " token; converting to "
                                                        + tokenType.toString() + " token");
                                        existingToken.setType(tokenType);
                                        tokenRepository.save(existingToken);
                                        log.info("existing token saved");
                                }

                                url += "?token=" + existingToken.getToken();
                                log.info("existing token; reset link = {}, expiration = {} ", url,
                                                tokenExpirationString);

                        } else {
                                log.info("creating new token for reset");
                                String tokenString = UUID.randomUUID().toString();
                                Token newToken = new Token(user, tokenString, tokenType);
                                tokenExpirationString = newToken.getExpirationDate().toString();
                                tokenRepository.save(newToken);

                                log.info("new token saved");

                                // log.info("token exp after save = "
                                // + tokenExpirationString);
                                // log.info("token exp findAgain = " + tokenRepository
                                // .findByToken(newToken.getToken()).get().getExpirationDate().toString());

                                url += "?token=" + newToken.getToken();
                                log.info("new token; reset link = {}, expiration = {} ", url,
                                                tokenExpirationString);

                        }

                        message2 += "The above link will expire on " + tokenExpirationString + ".";

                        if (isExistingTokenFound) {
                                log.info("Add message that previoius existing tokens are now invalid");

                                message2 += EXISTING_TOKEN_MESSAGE;
                        }

                        AuthEmail authEmail = new AuthEmail(
                                        user.getEmail(),
                                        user.getUsername(),
                                        subject + " - AshDelaCruz.com",
                                        message1,
                                        url,
                                        message2);

                        emailService.htmlAuthSend(authEmail);
                        log.info("authEmail sent to {} ", user.getEmail());

                } else {
                        log.error("user not found for email " + email);
                }
        }

        public ResponseEntity<?> resetPassword(String newPassword, String token) {

                ResponseEntity<Object> response;

                if (newPassword == null || newPassword.isEmpty()) {
                        response = this.responseService.generateResponse("newPassword required",
                                        HttpStatus.UNPROCESSABLE_ENTITY, null);
                        log.error("RETURN response = {}", response.toString());
                        return response;
                }
                log.info("newPassword found");

                if (!tokenService.isTokenFound(token)) {
                        response = this.responseService.generateResponse("Token invalid",
                                        HttpStatus.UNPROCESSABLE_ENTITY, null);
                        log.error("RETURN response = {}", response.toString());
                        return response;
                }
                log.info("token exists");

                if (tokenService.isTokenExpired(token)) {
                        response = this.responseService.generateResponse("Token expired",
                                        HttpStatus.UNPROCESSABLE_ENTITY, null);

                        log.error("RETURN response = {}", response.toString());
                        return response;
                }
                log.info("token is not expired");

                if (!tokenService.isTokenCorrectType(token, EToken.RESET_PASS)) {
                        response = this.responseService.generateResponse("Token invalid",
                                        HttpStatus.UNPROCESSABLE_ENTITY, null);

                        log.error("RETURN response = {}", response.toString());
                        return response;
                }
                log.info("token is correct type {}", EToken.RESET_PASS);

                User user = tokenService.getUserByToken(token);
                log.info("user found for token; currentUname = {}", user.getUsername());

                user.setPassword(encoder.encode(newPassword));
                log.info("updated pass for user");

                userRepository.save(user);
                log.info("user saved");

                tokenService.deleteUsedToken(token);
                log.info("delete used token");

                emailService.sendResetPassEmail(user);

                response = this.responseService.generateResponse("Sucessfully reset password", HttpStatus.ACCEPTED,
                                null);
                log.info("RETURN response = {}", response.toString());
                return response;

        }

        public ResponseEntity<?> resetUsername(String newUsername, String token) {
                ResponseEntity<Object> response;

                if (newUsername == null || newUsername.isEmpty()) {
                        response = this.responseService.generateResponse("newUsername required",
                                        HttpStatus.UNPROCESSABLE_ENTITY, null);
                        log.error("RETURN response = {}", response.toString());
                        return response;
                }
                log.info("newUsername found = {}", newUsername);

                if (!tokenService.isTokenFound(token)) {
                        response = this.responseService.generateResponse("Token invalid",
                                        HttpStatus.UNPROCESSABLE_ENTITY, null);
                        log.error("RETURN response = {}", response.toString());
                        return response;
                }
                log.info("token exists");

                if (tokenService.isTokenExpired(token)) {
                        response = this.responseService.generateResponse("Token expired",
                                        HttpStatus.UNPROCESSABLE_ENTITY, null);
                        log.error("RETURN response = {}", response.toString());
                        return response;
                }
                log.info("token is not expired");

                if (!tokenService.isTokenCorrectType(token, EToken.RESET_UNAME)) {
                        response = this.responseService.generateResponse("Token invalid",
                                        HttpStatus.UNPROCESSABLE_ENTITY, null);
                        log.error("RETURN response = {}", response.toString());
                        return response;
                }
                log.info("token is correct type {}", EToken.RESET_UNAME);

                if (userRepository.existsByUsername(newUsername)) {
                        response = this.responseService.generateResponse("Username already in use",
                                        HttpStatus.UNPROCESSABLE_ENTITY, null);
                        log.error("RETURN response = {}", response.toString());
                        return response;
                }
                log.info("newUsername is NOT already in use");

                User user = tokenService.getUserByToken(token);
                log.info("user found for token; currentUname = {}", user.getUsername());

                user.setUsername(newUsername);
                log.info("update username for user");

                userRepository.save(user);
                log.info("user saved");

                tokenService.deleteUsedToken(token);
                log.info("delete used token");

                emailService.sendResetUnameEmail(user);

                response = this.responseService.generateResponse(newUsername, HttpStatus.ACCEPTED,
                                null);
                log.info("RETURN response = {}", response.toString());
                return response;

        }

        public ResponseEntity<?> resetUsernameAndPassword(String newUsername, String newPassword, String token) {

                ResponseEntity<Object> response;

                if (newUsername == null || newUsername.isEmpty()) {
                        response = this.responseService.generateResponse("newUsername required",
                                        HttpStatus.UNPROCESSABLE_ENTITY, null);
                        log.error("RETURN response = {}", response.toString());
                        return response;
                }
                log.info("newUsername found = {}", newUsername);

                if (newPassword == null || newPassword.isEmpty()) {
                        response = this.responseService.generateResponse("newPassword required",
                                        HttpStatus.UNPROCESSABLE_ENTITY, null);
                        log.error("RETURN response = {}", response.toString());
                        return response;
                }
                log.info("newPassword found");

                if (!tokenService.isTokenFound(token)) {
                        response = this.responseService.generateResponse("Token invalid",
                                        HttpStatus.UNPROCESSABLE_ENTITY, null);
                        log.error("RETURN response = {}", response.toString());

                        return response;
                }
                log.info("token exists");

                if (tokenService.isTokenExpired(token)) {
                        response = this.responseService.generateResponse("Token expired",
                                        HttpStatus.UNPROCESSABLE_ENTITY, null);
                        log.error("RETURN response = {}", response.toString());
                        return response;
                }
                log.info("token is NOT expired");

                if (!tokenService.isTokenCorrectType(token, EToken.RESET_UNAME_AND_PASS)) {
                        response = this.responseService.generateResponse("Token invalid",
                                        HttpStatus.UNPROCESSABLE_ENTITY, null);
                        log.error("RETURN response = {}", response.toString());
                        return response;
                }
                log.info("token is correct type {}", EToken.RESET_UNAME_AND_PASS);

                if (userRepository.existsByUsername(newUsername)) {
                        response = this.responseService.generateResponse("Username already in use",
                                        HttpStatus.UNPROCESSABLE_ENTITY, null);
                        log.error("RETURN response = {}", response.toString());
                        return response;
                }
                log.info("newUsername is NOT already in use");

                User user = tokenService.getUserByToken(token);
                log.info("user found for token; currentUname = {}", user.getUsername());

                user.setUsername(newUsername);
                user.setPassword(encoder.encode(newPassword));
                log.info("update uname and pass for user");

                userRepository.save(user);
                log.info("user saved");

                tokenService.deleteUsedToken(token);
                log.info("delet used token");

                emailService.sendResetUnameAndPassEmail(user);

                response = this.responseService.generateResponse("Sucessfully reset username and password",
                                HttpStatus.ACCEPTED,
                                null);
                log.info("RETURN response = {}", response.toString());
                return response;
        }

        public ResponseEntity<?> deleteAccount(LoginRequest loginRequest) {

                // If credentials are invalid, flow stops here and responds with error based on
                // AuthEntryPoint.commence()
                Authentication authentication = authenticationManager.authenticate(
                                new UsernamePasswordAuthenticationToken(loginRequest.getUsername(),
                                                loginRequest.getPassword()));

                ResponseEntity<Object> response;

                String loggedInUserID = ((UserDetailsImpl) SecurityContextHolder.getContext().getAuthentication()
                                .getPrincipal()).getId();
                log.info("the user ID who is currently logged in = {}", loggedInUserID);

                UserDetailsImpl toBeDeletedUser = (UserDetailsImpl) authentication.getPrincipal();
                String toBeDeletedUserID = toBeDeletedUser.getId();
                log.info("the user ID whose account is to be deleted = {}", toBeDeletedUserID);

                // Make sure the user to be deleted is the same as the currently logged in user
                if (!loggedInUserID.equals(toBeDeletedUserID)) {
                        response = this.responseService.generateResponse(
                                        "Provided creds are different from the currently logged in user",
                                        HttpStatus.UNAUTHORIZED,
                                        null);
                        log.error("RETURN response = {}", response);
                        return response;
                }

                log.info("loggedInUserID is the same as toBeDeletedUserID");

                // At this point, the user must exist so delete them from repo
                User databaseUser = userRepository.findById(toBeDeletedUserID).get();
                String name = databaseUser.getUsername();
                String toEmail = databaseUser.getEmail();
                log.info("databaseUser found for ID {}; databaseUser ID = {} ", toBeDeletedUserID,
                                databaseUser.getId());

                userRepository.delete(databaseUser);
                log.info("user deleted from database");

                // Send reset creds link to email
                NotificationEmail notificationEmail = new NotificationEmail(
                                toEmail,
                                name,
                                this.DELETE_ACCOUNT_SUBJECT,
                                this.DELETE_ACCOUNT_MESSAGE);
                emailService.htmlNotificationSend(notificationEmail);
                log.info("notificaiton email sent to {}", toEmail);

                response = this.responseService.generateResponse("Sucessfully deleted account, logging out...",
                                HttpStatus.ACCEPTED, null);
                log.info("RETURN response = {} ", response.toString());
                return response;

        }

}
