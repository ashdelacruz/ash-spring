package com.ashdelacruz.spring.payload.request;

import jakarta.validation.constraints.NotBlank;
import lombok.Data;
import lombok.EqualsAndHashCode;

@Data
@EqualsAndHashCode(callSuper=true)
public class ResetRequest extends CredentialsRequest{


    @NotBlank
    private String token;

    // public String getToken() {
    //     return token;
    // }

    // public void setToken(String token) {
    //     this.token = token;
    // }

    // @Override
    // public String toString() {
    //     return "ResetRequest [token=" + token + "]";
    // }

    

    

    
}