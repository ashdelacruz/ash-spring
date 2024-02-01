package com.ashdelacruz.spring.models.mongodb.collections;

import java.util.Date;
import java.util.concurrent.TimeUnit;

import org.springframework.data.annotation.Id;
import org.springframework.data.mongodb.core.mapping.DBRef;
import org.springframework.data.mongodb.core.mapping.Document;

import com.ashdelacruz.spring.models.enums.EToken;

import jakarta.persistence.FetchType;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.OneToOne;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import lombok.Data;

// @Entity
@Document(collection = "tokens")
@Data
 
public class Token {
    private static final int EXPIRATION = 60 * 60 * 24;

    @Id
    @GeneratedValue(strategy = GenerationType.AUTO)
    private String id;

    @NotBlank
    @Size(max = 36)
    private String token;

    // @NotBlank
    // @Size(min = 5, max = 20)
    @DBRef
    private TokenType type;

    @OneToOne(targetEntity = User.class, fetch = FetchType.EAGER)
    @JoinColumn(nullable = true, name = "_id")
    private User user;

    private Date expirationDate;

    public Token() {

    }

    public Token(User user, String token) {
        this.user = user;
        this.token = token;
        this.expirationDate = new Date(System.currentTimeMillis() +
                TimeUnit.MINUTES.toMillis(EXPIRATION));
    }

    public Token(User user, String token, TokenType type) {
        this.user = user;
        this.token = token;
        this.type = type;
        this.expirationDate = new Date(System.currentTimeMillis() +
                TimeUnit.MINUTES.toMillis(EXPIRATION));
    }

    public Token(User user, String token, TokenType type, int expirationMs) {
        this.user = user;
        this.token = token;
        this.type = type;
        this.expirationDate = new Date(System.currentTimeMillis() +
                TimeUnit.MINUTES.toMillis(expirationMs));
    }

    // public static int getExpiration() {
    //     return EXPIRATION;
    // }

    // public String getId() {
    //     return id;
    // }

    // public void setId(String id) {
    //     this.id = id;
    // }

    // public EToken getType() {
    //     return type;
    // }

    // public void setType(EToken type) {
    //     this.type = type;
    // }

    // public String getToken() {
    //     return token;
    // }

    // public void setToken(String token) {
    //     this.token = token;
    // }

    // public User getUser() {
    //     return user;
    // }

    // public void setUser(User user) {
    //     this.user = user;
    // }

    // public Date getExpirationDate() {
    //     return expirationDate;
    // }

    // public void setExpirationDate(Date expirationDate) {
    //     this.expirationDate = expirationDate;
    // }

    // @Override
    // public String toString() {
    //     return "Token [id=" + id + ", token=" + token + ", type=" + type + ", user=" + user + ", expirationDate="
    //             + expirationDate + "]";
    // }

}
