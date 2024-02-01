package com.ashdelacruz.spring.security.services;

import java.util.HashMap;
import java.util.Map;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;

import lombok.extern.slf4j.Slf4j;

@Service
@Slf4j
public class ResponseService {

        public ResponseEntity<Object> generateResponse(String message, HttpStatus status, Object data) {
        Map<String, Object> map = new HashMap<String, Object>();
            map.put("message", message);
            map.put("status", status.value());
            map.put("data", data);
            return new ResponseEntity<Object>(map,status);
    }
    
}
