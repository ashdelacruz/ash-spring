package com.ashdelacruz.spring.models.email;

import java.io.IOException;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.io.Resource;

import lombok.Data;
import lombok.extern.slf4j.Slf4j;

@Data
 @Slf4j
public class AuthEmail {
    private String toEmail;
    private String subject;
    private String name;
    private String message1;
    private String url;
    private String message2;
    private String template = "auth-email.html";

    // private final String LOGO_PATH = "classpath:media/adc_logo_yellow.png";

    public AuthEmail(String toEmail, String name,  String subject, String message1, String url, String message2) {
        this.toEmail = toEmail;
        this.subject = subject;
        this.name = name;
        this.message1 = message1;
        this.url = url;
        this.message2 = message2;

   
        // log.info("LOGO_PATH = {}", this.LOGO_PATH);
    }
    
    public AuthEmail(String toEmail, String name, String subject,  String message1, String url) {
        this.toEmail = toEmail;
        this.subject = subject;
        this.name = name;
        this.message1 = message1;
        this.url = url;

        // log.info("LOGO_PATH = {}", this.LOGO_PATH);
    }
    
    public AuthEmail(String toEmail, String name, String subject,  String message1) {
        this.toEmail = toEmail;
        this.subject = subject;
        this.name = name;
        this.message1 = message1;
     
        // log.info("LOGO_PATH = {}", this.LOGO_PATH);
    }
    
}
