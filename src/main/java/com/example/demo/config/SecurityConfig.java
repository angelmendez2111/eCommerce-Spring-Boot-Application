package com.example.demo.config;

import com.example.demo.repositories.UserRepository;
import com.example.demo.service.JwtService;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity
@RequiredArgsConstructor
public class SecurityConfig {

    private final UserRepository userRepository;
    private final JwtService jwtService;


    //Region "Security configuration with SecurityFilterChain"
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                .csrf(csrf -> csrf.disable())   // CSRF is disabled because JWT handles sessions authentication.
                .authorizeHttpRequests(auth-> auth  // Allows access to “/”
                        .requestMatchers("/").permitAll()   // Allows access to “/”
                        .requestMatchers("/images/**").permitAll() // Allows access to images
                        .requestMatchers("/index.html").permitAll() // Allows access to index.html
                        .requestMatchers("/api/auth/**").permitAll() //Allows access to authentication
                        .requestMatchers(HttpMethod.GET, "/api/products/**").permitAll() // Allows to obtain products
                        .requestMatchers("/api/auth/change-password").authenticated() // Authentication required

                        .anyRequest().authenticated() // Everything else requires authentication
                )
                .sessionManagement(session -> session
                        .sessionCreationPolicy(SessionCreationPolicy.STATELESS) // Does not use sessions, JWT handles authentication
                )
                .addFilterBefore(jwtAuthenticationFilter(), UsernamePasswordAuthenticationFilter.class); // Add authentication filtering with JWT

        return http.build();
    }


    //Region "JWT Authentication Filtering"
    // JwtService uses JwtAuthenticationFilter to validate JWT tokens.
    @Bean
    public JwtAuthenticationFilter jwtAuthenticationFilter(){
        //userDetailsService() is injected to load user data.
        return new JwtAuthenticationFilter(jwtService, userDetailsService());
    }

    //Region "Password encryption"
    //CryptPasswordEncoder encrypts passwords before saving them in the database.
    @Bean
    public PasswordEncoder passwordEncoder(){
        return new BCryptPasswordEncoder();
    }

    // Region "Authentication management"
    // AuthenticationManager is used to authenticate users.
    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration authConfig) throws Exception{
        return authConfig.getAuthenticationManager();
    }

    // Region "User services"
    // Load user data from the database searching by email.
    @Bean
    public UserDetailsService userDetailsService(){
        return username -> (UserDetails) userRepository.findByEmail(username)
                .orElseThrow(()-> new UsernameNotFoundException("User not found"));
    }

    // Region "Configuration of the DaoAuthenticationProvider"
    @Bean
    public DaoAuthenticationProvider authenticationProvider(){
        DaoAuthenticationProvider authProvider = new DaoAuthenticationProvider();
        authProvider.setUserDetailsService(userDetailsService());
        authProvider.setPasswordEncoder(passwordEncoder());
        return authProvider;
    }
}