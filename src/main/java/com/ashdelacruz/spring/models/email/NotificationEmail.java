package com.ashdelacruz.spring.models.email;

import java.io.IOException;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.io.Resource;

import lombok.Data;
import lombok.extern.slf4j.Slf4j;

@Data
@Slf4j
public class NotificationEmail {
    private String toEmail;
    private String subject;
    private String name;
    private String message1;
    private String message2;
    private String template = "notification-email.html";

    // @Value("classpath:media/adc_logo_yellow.png")
    // private final String LOGO_PATH = "classpath:media/adc_logo_yellow.png";

    public NotificationEmail(String toEmail, String name,  String subject, String message1) {
        this.toEmail = toEmail;
        this.subject = subject;
        this.name = name;
        this.message1 = message1;
        // log.info("LOGO_PATH = {}", this.LOGO_PATH);
    }

    public NotificationEmail(String toEmail, String name,  String subject, String message1, String message2) {
        this.toEmail = toEmail;
        this.subject = subject;
        this.name = name;
        this.message1 = message1;
        this.message2 = message2;
        log.info("NotificaitonEmailConstructor 2; message1 = {}, message2 = {}", this.message1, this.message2);
        // log.info("LOGO_PATH = {}", this.LOGO_PATH);
    }

    public NotificationEmail(String toEmail, String name) {
        this.toEmail = toEmail;
        this.name = name;
     
        // log.info("LOGO_PATH = {}", this.LOGO_PATH);
    }
}
