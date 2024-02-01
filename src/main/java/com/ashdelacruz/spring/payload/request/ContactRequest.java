package com.ashdelacruz.spring.payload.request;

import lombok.Data;

@Data
public class ContactRequest {

    private String[] names;
    private String[] emails;
    private String message;
    
}
