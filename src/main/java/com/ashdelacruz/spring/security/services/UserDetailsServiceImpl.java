package com.ashdelacruz.spring.security.services;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.ashdelacruz.spring.models.UserDetailsImpl;
import com.ashdelacruz.spring.models.mongodb.collections.User;
import com.ashdelacruz.spring.repository.UserRepository;

import lombok.extern.slf4j.Slf4j;

/**
 * Will be used for getting UsetDetails object,
 * and for configuring DaoAuthenticationProvider by
 * AuthenticationManagerBuilder.userDetailsService() method.
 */
@Service
@Slf4j
public class UserDetailsServiceImpl implements UserDetailsService {
    
    @Autowired
    UserRepository userRepository;

    /**
     * Get the full custom User object using UserRepository,
     * then build a UserDetails object using static build() method
     * @param username
     * @return
     * @throws UsernameNotFoundException
     */
    @Override
    @Transactional
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        User user = userRepository.findByUsername(username)
                .orElseThrow(() -> new UsernameNotFoundException("User Not Found with username: " + username));

        return UserDetailsImpl.build(user);
    }

    public List<UserDetails> loadAllUsers()  {

        List<User> userList = userRepository.findAll();

        log.info("userList = {}", Arrays.toString(userList.toArray()));

        List<UserDetails> userDetailsList = new ArrayList<UserDetails>();

        for(User user: userList) {
            userDetailsList.add(UserDetailsImpl.build(user));
        }

        log.info("userDetailsList = {}", Arrays.toString(userDetailsList.toArray()));



        return userDetailsList;
    }

}