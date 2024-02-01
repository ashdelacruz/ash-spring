package com.ashdelacruz.spring.controllers;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.ashdelacruz.spring.models.email.NotificationEmail;
import com.ashdelacruz.spring.payload.request.NotificationRequest;
import com.ashdelacruz.spring.services.EmailService;

import jakarta.validation.Valid;
import lombok.extern.slf4j.Slf4j;


// @CrossOrigin(origins = "http://localhost:80", maxAge = 3600, allowCredentials = "true")

@Slf4j
@RestController
@RequestMapping("/api/v1")
public class EmailController {

    @Autowired
    EmailService emailService;


    @PostMapping("/send-email")
    public String sendEmail(@Valid @RequestBody NotificationRequest notificationRequest) {
        
        emailService.send((notificationRequest.getEmail()),notificationRequest.getSubject(), notificationRequest.getMessage());

        return "Message queued.";
    }

    @PostMapping("/send-html-notification-email")
    public String testSendHtmlNotification(@Valid @RequestBody NotificationRequest notificationRequest) {
        NotificationEmail notificationEmail = new NotificationEmail(
            "earl.ashleigh.delacruz@gmail.com",
            "John Smith", 
            "Notification - AshDelaCruz.com", 
            "This is a notification");
 
        emailService.htmlNotificationSend(notificationEmail);
        return "Message queued.";
    }
    
}
