package com.ashdelacruz.spring.models.mongodb.collections;

import org.springframework.data.annotation.Id;
import org.springframework.data.mongodb.core.mapping.Document;

import com.ashdelacruz.spring.models.enums.ERole;
import com.ashdelacruz.spring.models.enums.EToken;

import lombok.Data;

@Document(collection = "token-type")
@Data
public class TokenType {
    @Id
    private String id;

    private EToken name;

    public TokenType() {

    }

    public TokenType(String id, EToken name) {
        this.id = id;
        this.name = name;
    }

    public TokenType(EToken name) {
        this.name = name;
    }


}
