package com.ashdelacruz.spring.services;

import java.util.HashMap;
import java.util.Map;
import java.util.Properties;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mail.javamail.JavaMailSenderImpl;
import org.springframework.mail.javamail.MimeMessageHelper;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Service;
import org.thymeleaf.context.Context;
import org.thymeleaf.spring3.SpringTemplateEngine;

import com.ashdelacruz.spring.models.email.AuthEmail;
import com.ashdelacruz.spring.models.email.NotificationEmail;
import com.ashdelacruz.spring.models.mongodb.collections.User;

import jakarta.mail.internet.MimeMessage;
import lombok.extern.slf4j.Slf4j;

@Service
@Slf4j
public class EmailService {

    @Autowired(required = false)
    private JavaMailSender emailSender;

    @Autowired
    private SpringTemplateEngine templateEngine;

    @Value("${fromEmail}")
    private String fromEmail;

    @Value("${fromName}")
    private String fromName;

    @Value("${devModeEmail}")
    private boolean devModeEmail;

    @Value("${myEmail}")
    private String myEmail;

    @Value("${contactUrl}")
    private String contactUrl;

    @Value("${loginUrl}")
    private String loginUrl;

    public final String RESET_PASS_SUBJECT = "Password Reset Successful - AshDelaCruz.com";
    public final String RESET_PASS_MESSAGE = "Your password has been successfully reset.";

    public final String RESET_UNAME_SUBJECT = "Username Reset Successful - AshDelaCruz.com";
    public final String RESET_UNAME_MESSAGE = "Your username has been successfully reset.";

    public final String RESET_UNAME_AND_PASS_SUBJECT = "Username and Password Reset Successful - AshDelaCruz.com";
    public final String RESET_UNAME_AND_PASS_MESSAGE = "Your username and password have been successfully reset.";

    public final String FORGOT_PASS_MESSAGE = "A request to reset your password has been submitted. Click the link below to reset your password.";
    public final String FORGOT_UNAME_MESSAGE = "A request to reset your username has been submitted. Click the link below to reset your username.";
    public final String FORGOT_UNAME_AND_PASS_MESSAGE = "A request to reset your username and password has been submitted. Click the link below to reset your username and password.";
    public final String ACCOUNT_ACTIVATION_MESSAGE = "A request to resend your account activation link has been submitted. Click the link below to login and activate your account.";

    public final String UNLOCK_SUBJECT = "Account Unlocked - AshDelaCruz.com";
    public final String UNLOCK_MESSAGE = "Your account has been unlocked by a moderator. Click the above link to try logging in again.";


    @Async
    public void send(String toEmail, String subject, String message) {
        log.info("email: {} subject: {} message: {}", toEmail, subject, message);

        try {
            // JavaMailSender emailSender = this.getJavaMailSender();
            MimeMessage mimeMessage = emailSender.createMimeMessage();

            MimeMessageHelper helper = new MimeMessageHelper(mimeMessage);

            if (this.devModeEmail) {
                log.info("devModeEmail is true, setting toEmail to personal email");
                helper.setTo(this.myEmail);
            } else {
                helper.setTo(toEmail);
            }

            helper.setFrom(this.fromEmail, this.fromName);
            helper.setSubject(subject);
            helper.setText(message, true);

            log.info("Email queued - My Own Email");

            emailSender.send(mimeMessage);

        } catch (Exception e) {
            log.error("Exception: " + e.getMessage());
        }
    }

    @Async
    public void htmlNotificationSend(NotificationEmail notificationEmail) {
        log.info("htmlNotificationemail = {}, subject = {}, message = {}", notificationEmail.getToEmail(),
                notificationEmail.getSubject(), notificationEmail.getMessage1());

        try {
            // JavaMailSender emailSender = this.getJavaMailSender();
            MimeMessage mimeMessage = emailSender.createMimeMessage();

            MimeMessageHelper helper = new MimeMessageHelper(mimeMessage);

            helper.setFrom(this.fromEmail, this.fromName);
            log.info("htmlNotificationfromEmail = {}, fromName = {}", this.fromEmail, this.fromName);

            if (this.devModeEmail) {
                log.info("devModeEmail is true, setting toEmail to personal email");
                notificationEmail.setToEmail(this.myEmail);
            }

            helper.setTo(notificationEmail.getToEmail());
            log.info("htmlNotificationtoEmail = {}", notificationEmail.getToEmail());

            helper.setSubject(notificationEmail.getSubject());
            log.info("htmlNotificationsubject = {}", notificationEmail.getSubject());

            // helper.setText(authEmail.getMessage(), true);
            // helper.set
            // helper.setText(authEmail.getMessage2(), true);

            // Thymeleaf Context
            Context context = new Context();
            log.info("htmlNotificationThymeleaf context = {}", context.toString());

            Map<String, Object> properties = new HashMap<String, Object>();
            properties.put("name", notificationEmail.getName());
            log.info("htmlNotificationmapping name property = {}", notificationEmail.getName());

            properties.put("message1", notificationEmail.getMessage1());
            log.info("htmlNotificationmapping message1 property = {}", notificationEmail.getMessage1());

            properties.put("message2", notificationEmail.getMessage2());
            log.info("htmlNotificationmapping message2 property = {}", notificationEmail.getMessage2());

            // context.setVariable("name", name);
            context.setVariables(properties);
            log.info("htmlNotificationproperties set for context");

            String htmlTemplate = templateEngine.process("notification-email.html", context);
            helper.setText(htmlTemplate, true);
            log.info("htmlNotificationsetting HTML template");

            boolean devTest = true;

            log.info("htmlNotificationmimeMessage = {}", mimeMessage.getContent().toString());

            emailSender.send(mimeMessage);
            log.info("htmlNotificationMessage queued");

        } catch (Exception e) {
            log.error("htmlNotificationException = {} ", e.getMessage());
        }
    }

    @Async
    public void htmlAuthSend(AuthEmail authEmail) {
        log.info("htmlAuthemail: {} subject: {} message1: {}", authEmail.getToEmail(), authEmail.getSubject(),
                authEmail.getMessage1());

        try {
            // JavaMailSender emailSender = this.getJavaMailSender();
            MimeMessage mimeMessage = emailSender.createMimeMessage();

            MimeMessageHelper helper = new MimeMessageHelper(mimeMessage);

            helper.setFrom(this.fromEmail, this.fromName);
            log.debug("htmlAuthfromEmail = {}, fromName = {}", this.fromEmail, this.fromName);

            if (this.devModeEmail) {
                log.info("devModeEmail is true, setting toEmail to personal email");
                authEmail.setToEmail(this.myEmail);
            }

            helper.setTo(authEmail.getToEmail());
            log.debug("htmlAuthtoEmail = {}", authEmail.getToEmail());

            helper.setSubject(authEmail.getSubject());
            log.debug("htmlAuthsubject = {}", authEmail.getSubject());

            // helper.setText(authEmail.getMessage(), true);
            // helper.set
            // helper.setText(authEmail.getMessage2(), true);

            // Thymeleaf Context
            Context context = new Context();
            log.debug("htmlAuthThymeleaf context = {}", context.toString());

            Map<String, Object> properties = new HashMap<String, Object>();
            properties.put("name", authEmail.getName());
            log.debug("htmlAuthmapping name property = {}", authEmail.getName());

            properties.put("message1", authEmail.getMessage1());
            log.debug("htmlAuthmapping message1 property = {}", authEmail.getMessage1());

            properties.put("url", authEmail.getUrl());
            log.debug("htmlAuthmapping url property = {}", authEmail.getUrl());

            properties.put("message2", authEmail.getMessage2());
            log.debug("htmlAuthmapping message2 property = {}", authEmail.getMessage2());

            // context.setVariable("name", name);
            context.setVariables(properties);
            log.debug("htmlAuthproperties set for context");

            String html = templateEngine.process("auth-email.html", context);
            helper.setText(html, true);
            log.debug("htmlAuthsetting HTML template");

            boolean devTest = true;

            log.info("htmlAuthmimeMessage = {}", mimeMessage.toString());

            emailSender.send(mimeMessage);
            log.info("htmlAuthMessage queued");

        } catch (Exception e) {
            log.error("htmlAuthException = {} ", e.getMessage());
        }
    }

    public void sendAccountLockedEmail(User user) {
        AuthEmail authEmail = new AuthEmail(
                user.getEmail(),
                user.getUsername(),
                ("Account Locked - AshDelaCruz.com"),
                "Your account has been locked for 24 hours due to too many failed login attempts.",
                contactUrl,
                "If you want your account unlocked sooner, please click the link above to contact an admin.");
        this.htmlAuthSend(authEmail);

    }

    public void sendResetPassEmail(User user) {
        NotificationEmail notificationEmail = new NotificationEmail(
                user.getEmail(),
                user.getUsername(),
                this.RESET_PASS_SUBJECT,
                this.RESET_PASS_MESSAGE);
        this.htmlNotificationSend(notificationEmail);
        log.info("notificaiton email sent to {}", user.getEmail());

    }

    public void sendResetUnameEmail(User user) {
        NotificationEmail notificationEmail = new NotificationEmail(
                user.getEmail(),
                user.getUsername(),
                this.RESET_UNAME_SUBJECT,
                this.RESET_UNAME_MESSAGE);
        notificationEmail.setName(user.getUsername());
        this.htmlNotificationSend(notificationEmail);

        log.info("notificaiton email sent to {}", user.getEmail());

    }

    public void sendResetUnameAndPassEmail(User user) {

        NotificationEmail notificationEmail = new NotificationEmail(
                user.getEmail(),
                user.getUsername(),
                this.RESET_UNAME_AND_PASS_SUBJECT,
                this.RESET_UNAME_AND_PASS_MESSAGE);
        notificationEmail.setName(user.getUsername());
        this.htmlNotificationSend(notificationEmail);
        log.info("notificaiton email sent to {}", user.getEmail());
    }

    public void sendAccountUnlockedEmail(User user) {

        AuthEmail authEmail = new AuthEmail(
                user.getEmail(),
                user.getUsername(),
                this.UNLOCK_SUBJECT,
                this.loginUrl,
                this.UNLOCK_MESSAGE);
                authEmail.setName(user.getUsername());
        this.htmlAuthSend(authEmail);
        log.info("auth email sent to {}", user.getEmail());
    }

    // private SimpleMailMessage constructEmail(String subject, String body,
    // User user) {
    // SimpleMailMessage email = new SimpleMailMessage();
    // email.setSubject(subject);
    // email.setText(body);
    // email.setTo(user.getEmail());
    // email.setFrom(env.getProperty("support.email"));
    // return email;
    // }
}
