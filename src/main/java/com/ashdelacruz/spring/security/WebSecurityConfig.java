package com.ashdelacruz.spring.security;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import com.ashdelacruz.spring.models.enums.ERole;
import com.ashdelacruz.spring.security.jwt.AuthEntryPointJwt;
import com.ashdelacruz.spring.security.jwt.AuthTokenFilter;
import com.ashdelacruz.spring.security.services.UserDetailsServiceImpl;

import lombok.extern.slf4j.Slf4j;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity // <-- provides AOP security on methods. It enables @PreAuthorize,
                      // @PostAuthorize, it also supports JSR-250
// (securedEnabled = true,
// jsr250Enabled = true,
// prePostEnabled = true) // by default
@Slf4j
public class WebSecurityConfig {
    @Autowired
    UserDetailsServiceImpl userDetailsService;

    @Autowired
    private AuthEntryPointJwt authEntryPoint;


    @Bean
    public AuthTokenFilter authenticationJwtTokenFilter() {
        return new AuthTokenFilter();
    }

    @Bean
    public DaoAuthenticationProvider authenticationProvider() {
        DaoAuthenticationProvider authProvider = new DaoAuthenticationProvider();

        authProvider.setUserDetailsService(userDetailsService);
        authProvider.setPasswordEncoder(passwordEncoder());

        return authProvider;
    }

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration authConfig) throws Exception {
        return authConfig.getAuthenticationManager();
    }

    /**
     * Need PasswordEncoder for the DaoAuthenticationProvider.
     * If we don’t specify, it will use plain text.
     * 
     * @return
     */
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        log.info("http = {}", http.toString());

        http.csrf(csrf -> csrf.disable())
                // .exceptionHandling(exception ->
                // exception.authenticationEntryPoint(authEntryPoint))
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers("/api/auth/**").permitAll()
                        .requestMatchers("/api/mod/**").hasRole("MODERATOR")
                        // .requestMatchers("/api/demo/**").permitAll()
                        // .requestMatchers("/api/test/**").permitAll()
                        // .requestMatchers("/api/stream/**").hasRole("USER")
                        // .requestMatchers("/api/v1/**").permitAll()
                        // .requestMatchers(HttpMethod.OPTIONS, "/**").permitAll()
                        .anyRequest().authenticated())
                // .httpBasic(httpBasic -> httpBasic.authenticationEntryPoint(authEntryPoint))
                // .httpBasic(Customizer.withDefaults())
                .authenticationProvider(authenticationProvider())
                .addFilterBefore(authenticationJwtTokenFilter(), UsernamePasswordAuthenticationFilter.class)
                .exceptionHandling(exception -> exception.authenticationEntryPoint(authEntryPoint));
                // .accessDeniedHandler(authorizationHandler))
                // .formLogin(login -> login
                //         .loginPage("/api/auth/login")
                //         // .failureHandler(loginFailureHandler)
                //         // .successHandler(loginSuccessHandler)
                //         .permitAll())
                // .logout(logout -> logout.logoutUrl("/api/auth/logout")
                //         .permitAll()
                //         .invalidateHttpSession(true)
                //         .deleteCookies("access_token"));
  

        return http.build();
    }
}