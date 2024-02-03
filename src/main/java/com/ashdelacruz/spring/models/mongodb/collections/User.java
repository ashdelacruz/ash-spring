package com.ashdelacruz.spring.models.mongodb.collections;

import java.util.Date;
import java.util.HashSet;
import java.util.Set;

import org.springframework.data.annotation.Id;
import org.springframework.data.mongodb.core.mapping.DBRef;
import org.springframework.data.mongodb.core.mapping.Document;

import com.ashdelacruz.spring.models.UserDetailsImpl;

import jakarta.persistence.Column;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import lombok.Data;

//@Document annotation specifies domain object to be persisted to MongoDB
@Document(collection = "users")
@Data
 
public class User {

    @Id
    @GeneratedValue(strategy = GenerationType.AUTO)
    private String id;

    @NotBlank
    @Size(min = 3, max = 50)
    private String username;

    @NotBlank
    @Size(min = 6, max = 254)
    @Email
    private String email;

    @NotBlank
    @Size(min = 8, max = 120)
    private String password;

    private Date lastLogin;

    // @Column(name = "failed_attempt")
    private int failedLoginAttempts;

    // @Column(name = "lock_time")
    private Date lockTime;

    @NotBlank
    private boolean isEnabled;

    // @Column(name = "account_non_locked")
    private boolean accountNonLocked;

    @DBRef
    private Set<Role> roles = new HashSet<>();

    @DBRef
    private Set<Preference> preferences = new HashSet<>();

    public User() {

    }

    public User(String username, String email, String password) {
        this.username = username;
        this.email = email;
        this.password = password;
        this.isEnabled = false;
    }

    //For Demo users
    public User(
        String id, 
        String username, 
        String email, 
        Date lastLogin, 
        int failedLoginAttempts, 
        Date lockTime, 
        boolean isEnabled, 
        boolean accountNonLocked, 
        Set<Role> roles, 
        Set<Preference> preferences) {

        this.id = id;
        this.username = username;
        this.email = email;
        this.password = "xxxxxxxx";
        this.lastLogin = lastLogin;
        this.failedLoginAttempts = failedLoginAttempts;
        this.lockTime = lockTime;
        this.isEnabled = isEnabled;
        this.accountNonLocked = accountNonLocked;
        this.roles = roles;
        this.preferences = preferences;
    }

    // public User(UserDetailsImpl userDetails) {
    //     this.id = userDetails.getId();
    //     this.username = userDetails.getUsername();
    //     this.email = userDetails.getEmail();
    //     this.password = userDetails.getPassword();
    //     this.isEnabled = userDetails.isEnabled();
    //     this.lastLogin = userDetails.getLastLogin();
    //     this.failedLoginAttempts = userDetails.getFailedLoginAttempts();

    // }

    // public String getId() {
    //     return id;
    // }

    // public void setId(String id) {
    //     this.id = id;
    // }

    // public int getStatus() {
    //     return status;
    // }

    // public void setStatus(int status) {
    //     this.status = status;
    // }

    // public String getUsername() {
    //     return username;
    // }

    // public void setUsername(String username) {
    //     this.username = username;
    // }

    // public String getEmail() {
    //     return email;
    // }

    // public void setEmail(String email) {
    //     this.email = email;
    // }

    // public Set<Role> getRoles() {
    //     return roles;
    // }

    // public void setRoles(Set<Role> roles) {
    //     this.roles = roles;
    // }

    // public String getPassword() {
    //     return password;
    // }

    // public void setPassword(String password) {
    //     this.password = password;
    // }

    // public Date getLastLogin() {
    //     return lastLogin;
    // }

    // public void setLastLogin(Date lastLogin) {
    //     this.lastLogin = lastLogin;
    // }

    // public int getPasswordAttempts() {
    //     return passwordAttempts;
    // }

    // public void setPasswordAttempts(int passwordAttempts) {
    //     this.passwordAttempts = passwordAttempts;
    // }

    // public Set<Preference> getPreferences() {
    //     return preferences;
    // }

    // public void setPreferences(Set<Preference> preferences) {
    //     this.preferences = preferences;
    // }

    // public Set<Role> getRolesFromAuthority(Collection<? extends GrantedAuthority> authorities) {
    //     return authorities.stream()
    //             .map(item -> (Role) item.getAuthority().toString())
    //             .collect(Collectors.toSet());
    // }

}