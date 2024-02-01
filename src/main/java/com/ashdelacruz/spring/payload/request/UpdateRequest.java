package com.ashdelacruz.spring.payload.request;

import jakarta.validation.constraints.NotBlank;
import lombok.Data;
import lombok.EqualsAndHashCode;

@Data
@EqualsAndHashCode(callSuper=true)
public class UpdateRequest extends CredentialsRequest {

    @NotBlank
    private String id;

    @NotBlank
    private String password;

    public UpdateRequest() {
        super();
    }

    // public String getId() {
    //     return id;
    // }

    // public void setId(String userID) {
    //     this.id = userID;
    // }

    // public String getPassword() {
    //     return password;
    // }

    // public void setPassword(String password) {
    //     this.password = password;
    // }

    // @Override
    // public String toString() {
    //     return "UpdateRequest [id=" + id + ", password=" + password + "]";
    // }

 

}