package com.demos.SpringSecurity.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableMethodSecurity
public class SecurityConfig {

    @Bean
    PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    UserDetailsService userDetailsService() {
        UserDetails normalUser = User.builder()
                .username("normalUser")
                .password(passwordEncoder().encode("normalUser"))
                .roles("NORMAL")
                .build();

        UserDetails adminUser = User.builder()
                .username("adminUser")
                .password(passwordEncoder().encode("adminUser"))
                .roles("ADMIN", "NORMAL")
                .build();

        InMemoryUserDetailsManager inMemoryUserDetailsManager = new InMemoryUserDetailsManager(normalUser, adminUser);
        return inMemoryUserDetailsManager;

    }

    @Bean
    SecurityFilterChain filterChain(HttpSecurity httpSecurity) throws Exception {
        httpSecurity
                .authorizeHttpRequests(
                        (requests) -> requests
                                .requestMatchers("/home/public")
                                .permitAll()
                                .anyRequest()
                                .authenticated())
                .formLogin(Customizer.withDefaults());

        return httpSecurity.build();
    }
}

// @Bean
// SecurityFilterChain filterChain(HttpSecurity httpSecurity) throws Exception {
// httpSecurity
// .authorizeHttpRequests(
// (requests) -> requests
// .requestMatchers("/home/admin")
// .hasRole("ADMIN")
// .requestMatchers("/home/normal")
// .hasRole("NORMAL")
// .requestMatchers("/home/public")
// .permitAll()
// .anyRequest()
// .authenticated())
// .formLogin(Customizer.withDefaults());

// return httpSecurity.build();
// }