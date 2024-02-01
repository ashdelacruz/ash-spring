package com.ashdelacruz.spring.controllers;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.io.Resource;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import lombok.extern.slf4j.Slf4j;
import reactor.core.publisher.Mono;

/**
 * In this class we are able to secure methods in our APIS using
 * the @PreAuthorize annotation becuase we used @EnableMethodSecurity
 * in the WebSecurityConfig class
 */
// @CrossOrigin(origins = "*", maxAge = 3600)
// @CrossOrigin(origins = "http://localhost:80", maxAge = 3600, allowCredentials="true")
@Slf4j
@RestController
@RequestMapping("/api/test")
public class TestController {

     private static final Logger logger = LoggerFactory.getLogger(TestController.class);


    // @GetMapping(value = "nope", produces = "video/mp4") 
    // // @PreAuthorize("hasRole('USER') or hasRole('MODERATOR') or hasRole('ADMIN')")
    // public Mono<Resource> streamContent() {
    //     System.out.println("TESTING!!!");
    //     return streamService.retrieveContent("title");
    // }

    /**
     * For public access
     * @return
     */
    @GetMapping("/all")
    public String allAccess() {
        return "Public Content.";
    }

    /**
     * For users with ROLE_USER, ROLE_MODERATOR, or ROLE_ADMIN
     * @return
     */
    @GetMapping("/user")
    @PreAuthorize("hasRole('USER') or hasRole('MODERATOR') or hasRole('ADMIN')")
    public String userAccess() {
        return "User Content.";
    }

    /**
     * For users with ROLE_MODERATOR only
     * @return
     */
    @GetMapping("/mod")
    @PreAuthorize("hasRole('MODERATOR')")
    public String moderatorAccess() {
        logger.info("hit ");

        return "Moderator Board.";
    }

    /**
     * For users with ROLE_ADMIN only
     * @return
     */
    @GetMapping("/admin")
    @PreAuthorize("hasRole('ADMIN')")
    public String adminAccess() {
        return "Admin Board.";
    }
}