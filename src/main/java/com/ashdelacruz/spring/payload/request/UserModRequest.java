package com.ashdelacruz.spring.payload.request;

import java.util.List;

import com.ashdelacruz.spring.models.enums.ERole;

import lombok.Data;

@Data 
public class UserModRequest {
    // @NotBlank
    private List<String> ids;

    // @NotBlank
    private List<String> usernames;

    // @NotBlank
    private List<String> emails;

    // @NotBlank
    private ERole newRole;

    private boolean newStatus;

    public boolean getNewStatus() {
        return this.newStatus;
    }

    // public List<String> getIds() {
    //     return this.ids;
    // }

    // public void setIds(List<String> id) {
    //     this.ids = id;
    // }

    // public List<String> getUsernames() {
    //     return usernames;
    // }

    // public void setUsernames(List<String> usernames) {
    //     this.usernames = usernames;
    // }

    // public List<String> getEmails() {
    //     return emails;
    // }

    // public void setEmails(List<String> emails) {
    //     this.emails = emails;
    // }

    // public ERole getNewRole() {
    //     return this.newRole;
    // }

    // public void setNewRole(ERole role) {
    //     this.newRole = role;
    // }

    // public int getNewStatus() {
    //     return newStatus;
    // }

    // public void setNewStatus(int newStatus) {
    //     this.newStatus = newStatus;
    // }

    // @Override
    // public String toString() {
    //     return "UserModRequest [ids=" + ids + ", usernames=" + usernames + ", emails=" + emails + ", newRole=" + newRole
    //             + ", newStatus=" + newStatus + "]";
    // }

    
}
