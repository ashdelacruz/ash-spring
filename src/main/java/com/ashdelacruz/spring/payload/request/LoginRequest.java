package com.ashdelacruz.spring.payload.request;

import jakarta.validation.constraints.NotBlank;
import lombok.Data;

@Data
 
public class LoginRequest {
    @NotBlank
    private String username;

    @NotBlank
    private String password;

    private String token;


    // public String getUsername() {
    //     return username;
    // }

    // public void setUsername(String username) {
    //     this.username = username;
    // }

    // public String getPassword() {
    //     return password;
    // }

    // public void setPassword(String password) {
    //     this.password = password;
    // }


    // public String getToken() {
    //     return token;
    // }

    // public void setToken(String token) {
    //     this.token = token;
    // }
}