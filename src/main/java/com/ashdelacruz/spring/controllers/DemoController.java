package com.ashdelacruz.spring.controllers;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.apache.tomcat.util.http.fileupload.FileUtils;
import org.bson.json.JsonObject;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.io.ClassPathResource;
import org.springframework.core.io.Resource;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.util.ResourceUtils;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.ashdelacruz.spring.models.UserDetailsImpl;
import com.ashdelacruz.spring.models.enums.ERole;
import com.ashdelacruz.spring.models.mongodb.collections.Role;
import com.ashdelacruz.spring.models.mongodb.collections.User;
import com.ashdelacruz.spring.payload.request.UserModRequest;
import com.ashdelacruz.spring.security.services.ResponseService;
import com.ashdelacruz.spring.security.services.UserModService;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;

import jakarta.validation.Valid;
import lombok.extern.slf4j.Slf4j;

// @CrossOrigin(origins = "http://localhost:4200", maxAge = 3600, allowCredentials = "true")

@RestController
@RequestMapping("/api/demo/user")
@Slf4j
public class DemoController {

    @Autowired
    ResponseService responseService;

    // @Value("classpath:static/demoUserList.json")
    // Resource demoUserList;

    // @Autowired
    // UserModService userModService;
    // Demo Mode
    List<UserDetails> userDetailsList = new ArrayList<UserDetails>();

    long DAY_IN_MS = 1000 * 60 * 60 * 24;

    public void buildDemoUserList() {
        Set<Role> adminRole = new HashSet<>();
        adminRole.add(new Role(ERole.ROLE_ADMIN));
        adminRole.add(new Role(ERole.ROLE_MODERATOR));
        adminRole.add(new Role(ERole.ROLE_USER));
        adminRole.add(new Role(ERole.ROLE_GUEST));

        Set<Role> modRole = new HashSet<>();
        modRole.add(new Role(ERole.ROLE_MODERATOR));
        modRole.add(new Role(ERole.ROLE_USER));
        modRole.add(new Role(ERole.ROLE_GUEST));

        Set<Role> userRole = new HashSet<>();
        userRole.add(new Role(ERole.ROLE_USER));
        userRole.add(new Role(ERole.ROLE_GUEST));

        Set<Role> guestRole = new HashSet<>();
        guestRole.add(new Role(ERole.ROLE_GUEST));

        Set<Role> emptyRole = new HashSet<>();

        userDetailsList.add(UserDetailsImpl.build(new User(
                "656a736e6323e3392d11f68f",
                "admin1",
                "admin1@email.com",
                new Date(System.currentTimeMillis() - (7 * DAY_IN_MS)),
                0,
                null,
                true,
                true,
                adminRole,
                null)));

        userDetailsList.add(UserDetailsImpl.build(new User(
                "656bd48f6323e3392d11f699",
                "pending1",
                "pending1@email.com",
                null,
                0,
                null,
                false,
                true,
                emptyRole,
                null)));

        userDetailsList.add(UserDetailsImpl.build(new User(
                "656bd4936323e3392d11f69a",
                "approved1",
                "approved1@email.com",
                null,
                0,
                null,
                true,
                true,
                userRole,
                null)));

        userDetailsList.add(UserDetailsImpl.build(new User(
                "65a475b4911ab13f971a521c",
                "locked1",
                "locked1@email.com",
                new Date(System.currentTimeMillis() - (10 * DAY_IN_MS)),
                4,
                new Date(System.currentTimeMillis() - (1 * (DAY_IN_MS / 2))),
                true,
                false,
                modRole,
                null)));

        userDetailsList.add(UserDetailsImpl.build(new User(
                "656bd48b6323e3392d11f698",
                "mod1",
                "mod1@email.com",
                new Date(System.currentTimeMillis() - (8 * DAY_IN_MS)),
                0,
                null,
                true,
                true,
                modRole,
                null)));

        userDetailsList.add(UserDetailsImpl.build(new User(
                "65a47608911ab13f971a521e",
                "mod2",
                "mod2@email.com",
                new Date(System.currentTimeMillis() - (8 * DAY_IN_MS)),
                0,
                null,
                false,
                true,
                modRole,
                null)));

        userDetailsList.add(UserDetailsImpl.build(new User(
                "65a47625911ab13f971a521f",
                "user1",
                "user1@email.com",
                new Date(System.currentTimeMillis() - (9 * DAY_IN_MS)),
                0,
                null,
                true,
                true,
                userRole,
                null)));

        userDetailsList.add(UserDetailsImpl.build(new User(
                "65a475db911ab13f971a521d",
                "user2",
                "user2@email.com",
                new Date(System.currentTimeMillis() - (9 * DAY_IN_MS)),
                0,
                null,
                false,
                true,
                userRole,
                null)));

        userDetailsList.add(UserDetailsImpl.build(new User(
                "659b02357b1c4f1b6514bd71",
                "guest1",
                "guest1@email.com",
                new Date(System.currentTimeMillis() - (10 * DAY_IN_MS)),
                0,
                null,
                true,
                true,
                guestRole,
                null)));

        userDetailsList.add(UserDetailsImpl.build(new User(
                "65927db322ed8f4bc07233cc",
                "guest2",
                "guest2@email.com",
                new Date(System.currentTimeMillis() - (10 * DAY_IN_MS)),
                0,
                null,
                false,
                true,
                guestRole,
                null)));

        log.info("demoUSerList = {}", Arrays.toString(userDetailsList.toArray()));
    }

    /**
     * 
     * @return a list of all user info, not including passwords
     */
    @GetMapping("/list")
    public ResponseEntity<?> demoGetUserList() {

        if (userDetailsList.size() == 0) {
            this.buildDemoUserList();
        }

        Map<String, List<UserDetails>> responseData = new HashMap<String, List<UserDetails>>();
        responseData.put("users", userDetailsList);
        log.info("mapping responseUsers to responseData");

        ResponseEntity<Object> response = this.responseService.generateResponse("Request Successful", HttpStatus.OK,
                responseData);
        log.info("RETURN response = {}", response.toString());
        return response;

    }

    @PostMapping("/resend")
    public ResponseEntity<?> resend(@Valid @RequestBody UserModRequest resendRequest) {
        log.info("receieved request for resend");

        if (resendRequest.getIds() == null || resendRequest.getIds().isEmpty()) {
            ResponseEntity<Object> response = this.responseService.generateResponse("ids required",
                    HttpStatus.BAD_REQUEST, null);
            log.error("RETURN response = {}", response.toString());
            return response;

        }

        ResponseEntity<Object> response = this.responseService.generateResponse(
                "Successfully resent account activation email for user(s)", HttpStatus.OK,
                resendRequest.getIds());
        log.info("RETURN response = {}", response.toString());
        return response;
    }

    @PutMapping("/roles")
    public ResponseEntity<?> setUserRole(@Valid @RequestBody UserModRequest roleRequest) {
        log.info("receieved request for setUserRole");
        if (roleRequest.getIds() == null || roleRequest.getIds().isEmpty()) {
            ResponseEntity<Object> response = this.responseService.generateResponse("ids required",
                    HttpStatus.BAD_REQUEST, null);
            log.error("RETURN response = {}", response.toString());
            return response;

        }

        if (roleRequest.getNewRole() == null || roleRequest.getNewRole().toString().isEmpty()) {
            ResponseEntity<Object> response = this.responseService.generateResponse("newRole required",
                    HttpStatus.BAD_REQUEST, null);
            log.error("RETURN response = {}", response.toString());
            return response;

        }

        ResponseEntity<Object> response = this.responseService.generateResponse(
                "Successfully set role for user(s)", HttpStatus.OK,
                roleRequest.getIds());
        log.info("RETURN response = {}", response.toString());
        return response;
    }

    @PutMapping("/status")
    public ResponseEntity<?> setUserStatus(@Valid @RequestBody UserModRequest statusRequest) {
        log.info("receieved request for setUserStatus");
        ResponseEntity<Object> response;
        if (statusRequest.getIds() == null || statusRequest.getIds().isEmpty()) {
            response = this.responseService.generateResponse("ids required",
                    HttpStatus.BAD_REQUEST, null);
            log.error("RETURN response = {}", response.toString());
            return response;
        }

        response = this.responseService.generateResponse(
                "Successfully" + (statusRequest.getNewStatus() ? " enabled" : " disabled") + " user(s)", HttpStatus.OK,
                statusRequest.getIds());
        log.info("RETURN response = {}", response.toString());
        return response;
    }

    @PutMapping("/unlock")
    @PreAuthorize("hasRole('MODERATOR')")
    public ResponseEntity<?> unlockUser(@Valid @RequestBody UserModRequest unlockRequest) {
        log.info("receieved request for setUserStatus");
        ResponseEntity<Object> response;
        if (unlockRequest.getIds() == null || unlockRequest.getIds().isEmpty()) {
            response = this.responseService.generateResponse("ids required",
                    HttpStatus.BAD_REQUEST, null);
            log.error("RETURN response = {}", response.toString());
            return response;
        }
        response = this.responseService.generateResponse(
                "Successfully unlocked user(s)", HttpStatus.OK,
                unlockRequest.getIds());
        log.info("RETURN response = {}", response.toString());
        return response;
    }

    /**
     * Changes a User's roles
     * 
     * @param deleteRequest
     * @return
     */
    @DeleteMapping("/delete")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<?> deleteUser(@Valid @RequestBody UserModRequest deleteRequest) {
        log.info("receieved request for deleteUser");
        if (deleteRequest.getIds() == null || deleteRequest.getIds().isEmpty()) {
            ResponseEntity<Object> response = this.responseService.generateResponse("ids required",
                    HttpStatus.BAD_REQUEST, null);
            log.error("RETURN response = {}", response.toString());
            return response;
        }

        ResponseEntity<Object> response = this.responseService.generateResponse("Sucessfully deleted user(s)",
                HttpStatus.ACCEPTED, null);
        log.info("response = {}", response.toString());
        return response;

    }
}
