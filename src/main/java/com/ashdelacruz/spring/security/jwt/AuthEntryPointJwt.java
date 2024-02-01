package com.ashdelacruz.spring.security.jwt;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;

// import org.apache.tomcat.util.http.fileupload.IOUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.authentication.InsufficientAuthenticationException;
import org.springframework.security.authentication.LockedException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Map;
import org.apache.commons.io.IOUtils;

/**
 * Implements AuthenticationEntryPoint interface, and override commence() method
 * which will trigger anytime unauthenticated User requests a secured HTTP resource
 * and an AuthenticationException is thrown
 * 
 * User Auth Exception Priority:
 * 1. LockedException
 * 2. DisabledException
 * 3. BadCredentialsException
 * 4. InsufficientAuthenticationException ??
 */
@Component
@Slf4j
public class AuthEntryPointJwt implements AuthenticationEntryPoint {

    private static final Logger logger = LoggerFactory.getLogger(AuthEntryPointJwt.class);

    @Override
    public void commence(HttpServletRequest request, HttpServletResponse response, AuthenticationException authException)
            throws IOException, ServletException {

       response.setContentType(MediaType.APPLICATION_JSON_VALUE);
       response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);

       final Map<String, Object> body = new HashMap<>();

       if(authException.getClass() == BadCredentialsException.class) {
        logger.error("BadCredentialsException error!!!");
       
        body.put("status", HttpServletResponse.SC_UNAUTHORIZED); //SC_UNAUTHORIZED is 401 status code, indicating the request requires HTTP authentication
        body.put("error", "Unauthorized");
        body.put("message", "Invalid credentials");
       } else {
        logger.error("authException class = {}", authException.getClass());
       
        body.put("status", HttpServletResponse.SC_FORBIDDEN); //SC_UNAUTHORIZED is 401 status code, indicating the request requires HTTP authentication
        body.put("error", "Forbidden");
        body.put("message", authException.getLocalizedMessage());
       }

       body.put("path", request.getServletPath());

       final ObjectMapper mapper = new ObjectMapper();
       mapper.writeValue(response.getOutputStream(), body);
    }
}
