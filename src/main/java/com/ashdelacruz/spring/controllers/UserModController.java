package com.ashdelacruz.spring.controllers;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.ashdelacruz.spring.payload.request.UserModRequest;
import com.ashdelacruz.spring.security.services.ResponseService;
import com.ashdelacruz.spring.security.services.UserModService;

import jakarta.validation.Valid;
import lombok.extern.slf4j.Slf4j;

// @CrossOrigin(origins = "*")
@CrossOrigin(origins = "http://localhost:4200", maxAge = 3600, allowCredentials = "true")

@RestController
@RequestMapping("/api/mod/user")
@Slf4j
public class UserModController {
    @Autowired
    ResponseService responseService;

    @Autowired
    UserModService userModService;

    /**
     * 
     * @return a list of all user info, not including passwords
     */
    @GetMapping("/list")
    @PreAuthorize("hasRole('MODERATOR')")
    public ResponseEntity<?> getUserList() {
        log.info("receieved request for getUserList");
        return this.userModService.getAllUsers();

    }

    /**
     * 
     * @return a list of all user info, not including passwords
     */
    @GetMapping("/info")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<?> getUserInfo(@Valid @RequestBody UserModRequest userInfoRequest) {
        log.info("receieved request for getUserInfo");
        if ((userInfoRequest.getIds() == null || userInfoRequest.getIds().isEmpty()) &&
                (userInfoRequest.getUsernames() == null || userInfoRequest.getUsernames().isEmpty()) &&
                (userInfoRequest.getEmails() == null || userInfoRequest.getEmails().isEmpty())) {
            ResponseEntity<Object> response = this.responseService.generateResponse("Request contains no user info.",
                    HttpStatus.BAD_REQUEST, null);
            log.error("RETURN response = {}", response.toString());
            return response;
        }

        return this.userModService.getUserInfo(userInfoRequest.getIds(), userInfoRequest.getUsernames(),
                userInfoRequest.getEmails());

    }


    @PostMapping("/resend")
    @PreAuthorize("hasRole('MODERATOR')")
    public ResponseEntity<?> resend(@Valid @RequestBody UserModRequest resendRequest) {
        log.info("receieved request for resend");
     
        if (resendRequest.getIds() == null || resendRequest.getIds().isEmpty()) {
            ResponseEntity<Object> response = this.responseService.generateResponse("ids required",
                    HttpStatus.BAD_REQUEST, null);
            log.error("RETURN response = {}", response.toString());
            return response;

        }

        return this.userModService.resendAccountActivationLink(resendRequest.getIds());

    }

    /**
     * Changes a User's roles
     * 
     * @param roleRequest
     * @return
     */
    @PutMapping("/roles")
    @PreAuthorize("hasRole('MODERATOR')")
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

        return this.userModService.setRole(roleRequest.getIds(), roleRequest.getNewRole());

    }

    /**
     * Changes User(s) status
     * Expects a list of user IDs that are all the same status,
     * then their status set to the newStatus
     * 
     * @param userStatusRequest A list of user IDs, and the new status to set for
     *                          the user(s)
     * @return
     */
    @PutMapping("/status")
    @PreAuthorize("hasRole('MODERATOR')")
    public ResponseEntity<?> setUserStatus(@Valid @RequestBody UserModRequest userStatusRequest) {
        log.info("receieved request for setUserStatus");
        ResponseEntity<Object> response;
        if (userStatusRequest.getIds() == null || userStatusRequest.getIds().isEmpty()) {
            response = this.responseService.generateResponse("ids required",
                    HttpStatus.BAD_REQUEST, null);
            log.error("RETURN response = {}", response.toString());
            return response;
        }

        return this.userModService.setStatus(userStatusRequest.getIds(), userStatusRequest.getNewStatus());
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

        return this.userModService.deleteUser(deleteRequest.getIds());

    }

}