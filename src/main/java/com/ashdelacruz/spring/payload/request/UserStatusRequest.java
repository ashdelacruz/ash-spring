package com.ashdelacruz.spring.payload.request;

import jakarta.validation.constraints.NotBlank;
import lombok.Data;

@Data
 
public class UserStatusRequest {
    
    @NotBlank
    private String id;

    @NotBlank
    private int newStatus;

    // public String getId() {
    //     return this.id;
    // }

    // public void setId(String id) {
    //     this.id = id;
    // }

    // public int getNewStatus() {
    //     return this.newStatus;
    // }

    // public void setNewStatus(int status) {
    //     this.newStatus = status;
    // }
}