package com.ashdelacruz.spring.models.mongodb.collections;

import org.springframework.data.annotation.Id;
import org.springframework.data.mongodb.core.mapping.Document;

import com.ashdelacruz.spring.models.enums.ERole;

import lombok.Data;

@Document(collection = "roles")
@Data
 
public class Role {
    @Id
    private String id;

    private ERole name;

    public Role() {

    }

    public Role(String id, ERole name) {
        this.id = id;
        this.name = name;
    }

    public Role(ERole name) {
        this.name = name;
    }

    // public String getId() {
    //     return id;
    // }

    // public void setId(String id) {
    //     this.id = id;
    // }

    // public ERole getName() {
    //     return name;
    // }

    // public void setName(ERole name) {
    //     this.name = name;
    // }
}
