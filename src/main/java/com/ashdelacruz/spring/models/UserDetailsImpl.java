package com.ashdelacruz.spring.models;

import java.util.Collection;
import java.util.Date;
import java.util.List;
import java.util.Objects;
import java.util.stream.Collectors;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import com.ashdelacruz.spring.models.enums.ERole;
import com.ashdelacruz.spring.models.mongodb.collections.User;
import com.fasterxml.jackson.annotation.JsonIgnore;

import jakarta.validation.constraints.NotBlank;

/**
 * UserDetails Interface by default gives only uname, pass, and authorities.
 * This implementation will allow us to give id and email as well.
 */
public class UserDetailsImpl implements UserDetails {
    private static final long serialVersionUID = 1L;

    private String id;

    private String username;

    private String email;

    private boolean isEnabled;

    @JsonIgnore
    private String password;

    private Date lastLogin;

    private int failedLoginAttempts;


        // @Column(name = "lock_time")
        private Date lockTime;

        // @Column(name = "account_non_locked")
        private boolean accountNonLocked;

    private Collection<? extends GrantedAuthority> authorities;

    private String roleString;


    public UserDetailsImpl(String id, 
        String username, 
        String email, 
        boolean isEnabled, 
        String password, 
        Date lastLogin,
        int failedLoginAttempts,     
        Date lockTime,
        boolean accountNonLocked,
        Collection<? extends GrantedAuthority> authorities, 
        String roleString
    ) {
        this.id = id;
        this.username = username;
        this.email = email;
        this.isEnabled = isEnabled;
        this.password = password;
        this.lastLogin = lastLogin;
        this.failedLoginAttempts = failedLoginAttempts;
        this.lockTime = lockTime;
        this.accountNonLocked = accountNonLocked;
        this.authorities = authorities;
        this.roleString = roleString;
    }

    /**
     * Convert Set<Role> into List<GrantedAuthority> because it's
     * important to work with Spring Security and Authentication objects
     * 
     * @param user
     * @return
     */
    public static UserDetailsImpl build(User user) {
        List<GrantedAuthority> authorities = user.getRoles().stream()
                .map(role -> new SimpleGrantedAuthority(role.getName().name()))
                .collect(Collectors.toList());

        List<String> roleNames = user.getRoles().stream()
                .map(role -> {
                    return role.getName().toString();
                })
                .collect(Collectors.toList());

        return new UserDetailsImpl(
                user.getId(),
                user.getUsername(),
                user.getEmail(),
                user.isEnabled(),
                user.getPassword(),
                user.getLastLogin(),
                user.getFailedLoginAttempts(),
                user.getLockTime(),
                user.isAccountNonLocked(),
                authorities,
                roleString(roleNames));
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return authorities;
    }

    public static String roleString(List<String> roles) {
        if (roles.contains(ERole.ROLE_ADMIN.toString())) {
            return "Admin";
        } else if (roles.contains(ERole.ROLE_MODERATOR.toString())) {
            return "Moderator";
        } else if (roles.contains(ERole.ROLE_USER.toString())) {
            return "User";
        } else if (roles.contains(ERole.ROLE_GUEST.toString())) {
            return "Guest";
        } else if (roles.contains(ERole.ROLE_PENDING.toString())) {
            return "Pending";
        } else {
            return null;
        }
    }

    public String getId() {
        return id;
    }

    public String getEmail() {
        return email;
    }

    public void setEmail(String email) {
        this.email = email;
    }

    public String getRoleString() {
        return roleString;
    }

    public void setRoleString(String roleFriendlyName) {
        this.roleString = roleFriendlyName;
    }

    public static long getSerialversionuid() {
        return serialVersionUID;
    }

    public void setId(String id) {
        this.id = id;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    // public void setIsEnabled(boolean enabled) {
    //     this.isEnabled = enabled;
    // }

    public void setPassword(String password) {
        this.password = password;
    }

    public void setAuthorities(Collection<? extends GrantedAuthority> authorities) {
        this.authorities = authorities;
    }

    // public int getIsEnabled() {
    //     return isEnabled;
    // }

    public Date getLastLogin() {
        return lastLogin;
    }

    // public void setLastLogin(Date lastLogin) {
    //     this.lastLogin = lastLogin;
    // }

    public int getFailedLoginAttempts() {
        return failedLoginAttempts;
    }

    // public void setFailedLoginAttempts(int passwordAttempts) {
    //     this.failedLoginAttempts = passwordAttempts;
    // }

    public Date getLockTime() {
        return lockTime;
    }

    public void setLockTime(Date lockTime) {
        this.lockTime = lockTime;
    }

    @Override
    public String getPassword() {
        return password;
    }

    @Override
    public String getUsername() {
        return username;
    }

    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    @Override
    public boolean isAccountNonLocked() {
        return this.accountNonLocked;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    @Override
    public boolean isEnabled() {
        return this.isEnabled;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o)
            return true;
        if (o == null || getClass() != o.getClass())
            return false;
        UserDetailsImpl user = (UserDetailsImpl) o;
        return Objects.equals(id, user.id);
    }
}


// public class UserDetailsImpl implements UserDetails {
//     private static final long serialVersionUID = 1L;

//     private User user;

//     private String id;

//     // private String username;

//     // private String email;

//     // private Date lastLogin;

//     // private int failedLoginAttempts;

//     // private Date lockTime;

//     @JsonIgnore
//     private String password;

//     private Collection<? extends GrantedAuthority> authorities;

//     private String roleString;

//     // public UserDetailsImpl(String id, String username, String email, boolean isEnabled, String password, Date lastLogin,
//     //         int passwordAttempts,
//     //         Collection<? extends GrantedAuthority> authorities, String roleString) {
//     //     this.id = id;
//     //     this.username = username;
//     //     this.email = email;
//     //     this.is
//     //     this.password = password;
//     //     this.lastLogin = lastLogin;
//     //     this.failedLoginAttempts = passwordAttempts;
//     //     this.authorities = authorities;
//     //     this.roleString = roleString;
//     // }

//     // public UserDetailsImpl(User user) {
//     //     this.user = user;
//     // }

//     public UserDetailsImpl(User user, Collection<? extends GrantedAuthority> authorities, String roleString) {
//         this.user = user;
//         this.authorities = authorities;
//         this.roleString = roleString;
//     }

//     /**
//      * Convert Set<Role> into List<GrantedAuthority> because it's
//      * important to work with Spring Security and Authentication objects
//      * 
//      * @param user
//      * @return
//      */
//     public static UserDetailsImpl build(User user) {
//         log.info("building userDetailsImpl user = {}", user.toString());
//         List<GrantedAuthority> authorities = user.getRoles().stream()
//                 .map(role -> new SimpleGrantedAuthority(role.getName().name()))
//                 .collect(Collectors.toList());

//         List<String> roleNames = user.getRoles().stream()
//                 .map(role -> {
//                     return role.getName().toString();
//                 })
//                 .collect(Collectors.toList());

//         return new UserDetailsImpl(
//                 user,
//                 authorities,
//                 generateRoleString(roleNames));
//     }

 
//     public static String generateRoleString(List<String> roles) {
//         if (roles.contains(ERole.ROLE_ADMIN.toString())) {
//             return "Admin";
//         } else if (roles.contains(ERole.ROLE_MODERATOR.toString())) {
//             return "Moderator";
//         } else if (roles.contains(ERole.ROLE_USER.toString())) {
//             return "User";
//         } else if (roles.contains(ERole.ROLE_GUEST.toString())) {
//             return "Guest";
//         } else if (roles.contains(ERole.ROLE_PENDING.toString())) {
//             return "Pending";
//         } else {
//             return null;
//         }
//     }

//     public static long getSerialversionuid() {
//         return serialVersionUID;
//     }
    
//     public User getUser() {
//         return user;
//     }

//     public void setUser(User user) {
//         this.user = user;
//     }


//     public String getId() {
//         return user.getId();
//     }

//     public void setId(String id) {
//         user.setId(id);
//     }

//     @Override
//     public String getUsername() {
//         return user.getUsername();
//     }


//     public void setUsername(String username) {
//         user.setUsername(username);
//     }

//     public String getEmail() {
//         return user.getEmail();
//     }

//     public void setEmail(String email) {
//         user.setEmail(email);
//     }

//     @JsonIgnore
//     @Override
//     public String getPassword() {
//         return user.getPassword();
//     }

//     @JsonIgnore
//     public void setPassword(String password) {
//         user.setPassword(password);
//     }

//     public String getRoleString() {
//         return this.roleString;
//     }

//     public void setRoleString(String roleString) {
//         this.roleString = roleString;
//     }

//     @Override
//     public Collection<? extends GrantedAuthority> getAuthorities() {
//         return authorities;
//     }

//     public void setAuthorities(Collection<? extends GrantedAuthority> authorities) {
//        this.authorities = authorities;
//     }

//     public Date getLastLogin() {
//         return user.getLastLogin();
//     }

//     public void setLastLogin(Date lastLogin) {
//         user.setLastLogin(lastLogin);
//     }

//     public int getFailedLoginAttempts() {
//         return user.getFailedLoginAttempts();
//     }

//     public void setFailedLoginAttempts(int failedAttempts) {
//         user.setFailedLoginAttempts(failedAttempts);
//     }

//     @Override
//     public boolean isAccountNonExpired() {
//         return true;
//     }

//     @Override
//     public boolean isAccountNonLocked() {
//         return user.isAccountNonLocked();
//     }

//     public void setAccountNonLocked(boolean accountNonLocked) {
//         this.user.setAccountNonLocked(accountNonLocked);
//     }

//     @Override
//     public boolean isCredentialsNonExpired() {
//         return true;
//     }

//     @Override
//     public boolean isEnabled() {
//         return user.isEnabled();
//     }

//     public void setEnabled(boolean enabled) {
//         this.user.setEnabled(enabled);
//     }

//     @Override
//     public boolean equals(Object o) {
//         if (this == o)
//             return true;
//         if (o == null || getClass() != o.getClass())
//             return false;
//         UserDetailsImpl user = (UserDetailsImpl) o;
//         return Objects.equals(id, user.id);
//     }
// }
