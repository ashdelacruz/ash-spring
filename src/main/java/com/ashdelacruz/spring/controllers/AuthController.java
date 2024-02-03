package com.ashdelacruz.spring.controllers;

import java.util.Arrays;
import java.util.Date;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.logout.SecurityContextLogoutHandler;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.ashdelacruz.spring.models.UserDetailsImpl;
import com.ashdelacruz.spring.models.email.AuthEmail;
import com.ashdelacruz.spring.models.enums.ECredentialTypes;
import com.ashdelacruz.spring.models.enums.EToken;
import com.ashdelacruz.spring.models.mongodb.collections.Token;
import com.ashdelacruz.spring.models.mongodb.collections.User;
import com.ashdelacruz.spring.payload.request.ContactRequest;
import com.ashdelacruz.spring.payload.request.ForgotRequest;
import com.ashdelacruz.spring.payload.request.LoginRequest;
import com.ashdelacruz.spring.payload.request.ResetRequest;
import com.ashdelacruz.spring.payload.request.SignupRequest;
import com.ashdelacruz.spring.payload.request.UpdateRequest;
import com.ashdelacruz.spring.repository.TokenRepository;
import com.ashdelacruz.spring.repository.UserRepository;
import com.ashdelacruz.spring.security.services.AuthService;
import com.ashdelacruz.spring.security.services.ResponseService;
import com.ashdelacruz.spring.security.services.TokenService;
import com.ashdelacruz.spring.services.EmailService;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.validation.Valid;
import lombok.extern.slf4j.Slf4j;

// @CrossOrigin(origins = "*")
// @CrossOrigin(origins = "http://localhost:4200", maxAge = 3600, allowCredentials = "true")
@Slf4j
@RestController
@RequestMapping("/api/auth")
public class AuthController {
        // @Autowired
        // AuthenticationManager authenticationManager;

        @Autowired
        ResponseService responseService;

        @Autowired
        AuthService authService;

        @Autowired
        EmailService emailService;

        @Autowired
        UserRepository userRepository;

        @Autowired
        TokenService tokenService;

        @Autowired
        TokenRepository tokenRepository;

         @Value("${loginUrl}")
        private String loginUrl;

        @Value("${resetUrl}")
        private String resetUrl;

        private final String RESET_CREDS_RESPONSE = "Thank you. If the provided email is associated with a user account, you will receieve an email with a link to reset your ";
        private final String RESEND_ACTIVATION_RESPONSE = "Thank you. If the provided email is associated with a user account, you will receieve an email with a link to activate your account.";
       
        /**
         * -Check existing uname/email
         * -Create new User (with ROLE_USER if no role specified)
         * -Save User to database using UserRepository
         * 
         * @param signUpRequest
         * @return
         */
        @PostMapping("/signup")
        public ResponseEntity<?> signup(@Valid @RequestBody SignupRequest signUpRequest) {
                log.info("receieved request for signup");

                return this.authService.createAccountRequest(signUpRequest);
        }

        @PostMapping("/contact")
        public ResponseEntity<?> contact(@Valid @RequestBody ContactRequest contactRequest) {
                log.info("receieved request for contact");

                ResponseEntity<Object> response;

                if (contactRequest.getNames().length < 1) {
                        response = this.responseService.generateResponse("Name is required",
                                        HttpStatus.BAD_REQUEST, null);
                        log.error("RETURN response = {}", response.toString());
                        return response;
                }

                if (contactRequest.getEmails().length < 1) {
                        response = this.responseService.generateResponse("Email is required",
                                        HttpStatus.BAD_REQUEST, null);
                        log.error("RETURN response = {}", response.toString());
                        return response;
                }

                if (contactRequest.getMessage().length() < 1) {
                        response = this.responseService.generateResponse("Message is required",
                                        HttpStatus.BAD_REQUEST, null);
                        log.error("RETURN response = {}", response.toString());
                        return response;
                }

                log.info("contactRequest username = {}, email = {}, message = {}",
                                Arrays.toString(contactRequest.getNames()),
                                Arrays.toString(contactRequest.getEmails()), contactRequest.getMessage());

                return this.authService.contactFromUser(contactRequest);
        }

        /**
         * -Authenticate uname and pass
         * -Update SecurityContext using Authentication obejct
         * -Generate JWT
         * -Get UserDetails from Authentication object
         * -Response contains JWT in Cookies and UserDetails data
         * 
         * @param loginRequest
         * @return
         */
        @PostMapping("/login")
        public ResponseEntity<?> login(@Valid @RequestBody LoginRequest loginRequest) {

                log.info("receieved request for login");
                log.info("username = {}", loginRequest.getUsername());

                ResponseEntity<Object> response;

                Token token = null;
                // User may be attempting to activate account
                if (loginRequest.getToken() != null) {
                        log.info("request contains a token, attempt account activation");

                        if (!tokenService.isTokenFound(loginRequest.getToken())) {
                                response = this.responseService.generateResponse("Token invalid",
                                                HttpStatus.UNPROCESSABLE_ENTITY, null);
                                log.error("RETURN response = " + response.toString());

                                return response;
                        }

                        if (tokenService.isTokenExpired(loginRequest.getToken())) {
                                response = this.responseService.generateResponse("Token expired",
                                                HttpStatus.UNPROCESSABLE_ENTITY, null);
                                log.error("RETURN response = " + response.toString());
                                return response;
                        }

                        if (!tokenService.isTokenCorrectType(loginRequest.getToken(), EToken.LOGIN)) {
                                response = this.responseService.generateResponse("Token invalid",
                                                HttpStatus.UNPROCESSABLE_ENTITY, null);
                                log.error("RETURN response = " + response.toString());
                                return response;
                        }

                        log.info("token is valid");

                        token = tokenRepository.findByToken(loginRequest.getToken()).get();
                }


                // log.info("credentials are valid");

                return this.authService.authenticateUser(loginRequest, token);
        }

        /**
         * Clear the Cookie
         * 
         * @param loginRequest
         * @return
         */
        @PostMapping("/logout")
        public ResponseEntity<?> logout(HttpServletRequest request, HttpServletResponse response) {
                log.info("receieved request for logout");

                log.info("request = {}", request.toString());

                Authentication auth = SecurityContextHolder.getContext().getAuthentication();
                SecurityContextLogoutHandler logoutHandler = new SecurityContextLogoutHandler();

                if (auth != null) {
                        // new SecurityContextLogoutHandler().logout(request, response, auth);
                        logoutHandler.logout(request, response, auth);
                        SecurityContextHolder.getContext().setAuthentication(null);

                        log.info("RETURN " + HttpStatus.OK);
                        return ResponseEntity.ok().header(HttpHeaders.SET_COOKIE, "").body("Logout successful");
                } else {
                        log.error("RETURN " + HttpStatus.INTERNAL_SERVER_ERROR);
                        return ResponseEntity.internalServerError().body("Logout failed");
                }

        }

        /**
         * Used for updating a user's credentials
         * when they are already authenticated
         * 
         * @param updateRequest
         * @return A token that will be used to reset the user creds
         */
        @PutMapping("/update/{type}")
        @PreAuthorize("hasRole('GUEST')")
        public ResponseEntity<?> update(@Valid @PathVariable("type") ECredentialTypes type,
                        @Valid @RequestBody UpdateRequest updateRequest) {
                log.info("receieved request for update");

                log.info("type = {}", type);
                ResponseEntity<Object> response;

                if (updateRequest.getId() == null) {

                        response = this.responseService.generateResponse("User id required",
                                        HttpStatus.BAD_REQUEST, null);
                        log.error("RETURN response = {}", response.toString());
                        return response;

                }
                log.info("id = " + updateRequest.getId());

                UserDetailsImpl loggedInUser = (UserDetailsImpl) SecurityContextHolder.getContext().getAuthentication()
                                .getPrincipal();
                log.info("the user who is currently authenticated = {}", loggedInUser.getUsername());

                // Make sure the user to be deleted is the same as the currently logged in user
                if (!loggedInUser.getId().equals(updateRequest.getId())) {
                        response = this.responseService.generateResponse(
                                        "Provided user ID does not match currently logged in user ID",
                                        HttpStatus.UNAUTHORIZED,
                                        null);
                        log.error("RETURN response = {}", response.toString());
                        return response;
                }

                if (type == ECredentialTypes.email) {

                        return this.authService.updateEmail(updateRequest);

                } else if (type == ECredentialTypes.username) {

                        return this.authService.updateUsername(
                                        updateRequest,
                                        loggedInUser);

                } else if (type == ECredentialTypes.password) {

                        return this.authService.updatePassword(
                                        updateRequest,
                                        loggedInUser);

                } else {

                        response = this.responseService.generateResponse("Invalid type",
                                        HttpStatus.BAD_REQUEST, null);
                        log.error("RETURN response = {}", response.toString());
                        return response;
                }

        }

        @PostMapping("/forgot/{type}")
        public ResponseEntity<?> forgot(@Valid @PathVariable("type") ECredentialTypes type,
                        @Valid @RequestBody ForgotRequest forgotRequest) {
                log.info("receieved request for forgot");

                log.info("type = {} ", type);
                log.info("forgotRequest = {}", forgotRequest.toString());
                // return this.authService.forgotCredentials(type, forgotRequest);

                if (type == ECredentialTypes.account_activation_link) {

                        this.authService.sendResetLink(forgotRequest.getEmail(),
                                        this.emailService.ACCOUNT_ACTIVATION_MESSAGE,
                                        "Activate Account",
                                        this.loginUrl,
                                        EToken.LOGIN);

                } else if (type == ECredentialTypes.password) {

                        this.authService.sendResetLink(forgotRequest.getEmail(),
                                        this.emailService.FORGOT_PASS_MESSAGE,
                                        "Reset Password",
                                        this.resetUrl + "/" + type,
                                        EToken.RESET_PASS);

                } else if (type == ECredentialTypes.username) {

                        this.authService.sendResetLink(forgotRequest.getEmail(),
                                        this.emailService.FORGOT_UNAME_MESSAGE,
                                        "Reset Username",
                                        this.resetUrl + "/" + type,
                                        EToken.RESET_UNAME);

                } else if (type == ECredentialTypes.username_and_password) {

                        this.authService.sendResetLink(forgotRequest.getEmail(),
                                        this.emailService.FORGOT_UNAME_AND_PASS_MESSAGE,
                                        "Reset Username and Password",
                                        this.resetUrl + "/" + type,
                                        EToken.RESET_UNAME_AND_PASS);
                } else {

                        ResponseEntity<Object> response = this.responseService.generateResponse("Invalid type",
                                        HttpStatus.BAD_REQUEST,
                                        null);
                        log.error("RETURN response = {}", response.toString());
                        return response;
                }

                String responseMessage;
                if (type == ECredentialTypes.account_activation_link) {

                        responseMessage = this.RESEND_ACTIVATION_RESPONSE;

                } else {
                        responseMessage = this.RESET_CREDS_RESPONSE + type.toString().replace('_', ' ');

                }

                ResponseEntity<Object> response = this.responseService.generateResponse(responseMessage,
                                HttpStatus.ACCEPTED,
                                null);
                log.info("RETURN response = {}", response.toString());
                return response;
        }

        @PutMapping("/reset/{type}")
        public ResponseEntity<?> reset(@Valid @PathVariable("type") ECredentialTypes type,
                        @Valid @RequestBody ResetRequest resetRequest) {
                log.info("receieved request for reset");

                log.info("type = " + type);
                // return this.authService.resetCredentials(type, resetRequest);

                if (resetRequest.getToken() == null || resetRequest.getToken().isEmpty()) {
                        ResponseEntity<Object> response = this.responseService.generateResponse("Token is required",
                                        HttpStatus.BAD_REQUEST, null);
                        log.error("RETURN response = {}", response.toString());
                        return response;
                }

                if (type == ECredentialTypes.username) {

                        return this.authService.resetUsername(
                                        resetRequest.getNewUsername(),
                                        resetRequest.getToken());

                } else if (type == ECredentialTypes.password) {

                        return this.authService.resetPassword(
                                        resetRequest.getNewPassword(),
                                        resetRequest.getToken());

                } else if (type == ECredentialTypes.username_and_password) {

                        return this.authService.resetUsernameAndPassword(
                                        resetRequest.getNewUsername(),
                                        resetRequest.getNewPassword(),
                                        resetRequest.getToken());

                } else {

                        ResponseEntity<Object> response = this.responseService.generateResponse("Invalid type",
                                        HttpStatus.BAD_REQUEST, null);
                        log.error("RETURN response = {}", response.toString());
                        return response;
                }

        }

        /**
         * Changes a User's roles
         * 
         * @param deleteRequest
         * @return
         */
        @DeleteMapping("/delete")
        @PreAuthorize("hasRole('GUEST')")
        public ResponseEntity<?> deleteAccount(@Valid @RequestBody LoginRequest loginRequest) {
                log.info("receieved request for deleteAccount");

                log.info("loginRequest username = {}", loginRequest.getUsername());

                return this.authService.deleteAccount(loginRequest);
        }

}