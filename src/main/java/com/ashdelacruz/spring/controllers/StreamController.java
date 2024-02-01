package com.ashdelacruz.spring.controllers;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.io.Resource;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.ashdelacruz.spring.streaming.StreamService;

import lombok.extern.slf4j.Slf4j;
import reactor.core.publisher.Mono;

// @CrossOrigin(origins = "http://localhost:80", maxAge = 3600, allowCredentials="true")
@Slf4j
@RestController
@RequestMapping("/api/stream")
public class StreamController {
    
    @Autowired
    private StreamService streamService;
    
    @GetMapping(value = "{title}", produces = "video/mp4") 
    // @PreAuthorize("hasRole('USER') or hasRole('MODERATOR') or hasRole('ADMIN')")
    public Mono<Resource> streamContent(@PathVariable String title) { //, @RequestHeader("Range") String range) {
        System.out.println("TESTING!!! title = " + title);
        // System.out.println("TESTING!!! range = " + range);
        return streamService.retrieveContent(title);
    }
}
