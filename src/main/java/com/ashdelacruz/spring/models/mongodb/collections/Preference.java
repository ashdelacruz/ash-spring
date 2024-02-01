package com.ashdelacruz.spring.models.mongodb.collections;

import org.springframework.data.annotation.Id;
import org.springframework.data.mongodb.core.mapping.Document;

import com.ashdelacruz.spring.models.enums.EPreference;

import lombok.Data;

@Document(collection = "preference")
@Data
 
public class Preference {

    @Id
    private String id;

    private EPreference pref_key;

    private Object pref_value;

    public Preference(String id, EPreference pref_key) {
        this.id = id;
        this.pref_key = pref_key;
    }

    public Preference(EPreference pref_key) {

        this.pref_key = pref_key;
    }

    // public String getId() {
    //     return id;
    // }

    // public void setId(String id) {
    //     this.id = id;
    // }

    // public EPreference getPref_key() {
    //     return pref_key;
    // }

    // public void setPref_key(EPreference pref_key) {
    //     this.pref_key = pref_key;
    // }

    // public Object getPref_value() {
    //     return pref_value;
    // }

    // public void setPref_value(Object pref_value) {
    //     this.pref_value = pref_value;
    // }

}
