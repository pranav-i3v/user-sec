package com.pranav.authcore.config;

import com.pranav.authcore.security.filter.LoginAuthenticationFilter;
import com.pranav.authcore.security.filter.RegistrationFilter;
import com.pranav.authcore.security.filter.TokenAuthenticationFilter;
import com.pranav.authcore.security.provider.BearerTokenAuthenticationProvider;
import com.pranav.authcore.security.provider.LoginAuthenticationProvider;
import com.pranav.authcore.security.provider.RegistrationAuthenticationProvider;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import java.util.List;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity(prePostEnabled = true)
@RequiredArgsConstructor
public class SecurityConfig {

    private final LoginAuthenticationProvider loginAuthenticationProvider;
    private final RegistrationAuthenticationProvider registrationAuthenticationProvider;
    private final BearerTokenAuthenticationProvider bearerTokenAuthenticationProvider;

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder(12);
    }

    /**
     * AuthenticationManager with all custom providers
     */
    @Bean
    public AuthenticationManager authenticationManager() {
        return new ProviderManager(List.of(
            loginAuthenticationProvider,
            registrationAuthenticationProvider,
            bearerTokenAuthenticationProvider
        ));
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http,
                                                  LoginAuthenticationFilter loginAuthenticationFilter,
                                                  RegistrationFilter registrationFilter,
                                                  TokenAuthenticationFilter tokenAuthenticationFilter) throws Exception {
        http
            .csrf(AbstractHttpConfigurer::disable)
            .sessionManagement(session -> 
                session.sessionCreationPolicy(SessionCreationPolicy.STATELESS)
            )
            .authorizeHttpRequests(auth -> auth
                // Public endpoints (no authentication required)
                .requestMatchers(
                    "/api/auth/login",
                    "/api/auth/refresh",
                    "/api/auth/register",
                    "/actuator/health",
                    "/public/**"
                ).permitAll()
                // All other requests require authentication
                .anyRequest().authenticated()
            )
            // Add filters in order: Login/Register → Token validation
            .addFilterBefore(loginAuthenticationFilter, UsernamePasswordAuthenticationFilter.class)
            .addFilterBefore(registrationFilter, UsernamePasswordAuthenticationFilter.class)
            .addFilterBefore(tokenAuthenticationFilter, UsernamePasswordAuthenticationFilter.class);

        return http.build();
    }
}

