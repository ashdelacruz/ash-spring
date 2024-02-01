package com.ashdelacruz.spring.payload.request;

// import com.ashdelacruz.spring.models.enums.String;

import jakarta.validation.constraints.NotBlank;
import lombok.Data;

@Data
 
public class ForgotRequest {



    @NotBlank
    private String email;




   


}