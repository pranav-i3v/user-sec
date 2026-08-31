package com.pranav.authcore.config;

import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.persistence.autoconfigure.EntityScan;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.data.jpa.repository.config.EnableJpaRepositories;
import tools.jackson.databind.ObjectMapper;

/**
 * Auto-configuration for Auth-Server-Core library.
 * 
 * This configuration is automatically picked up when the library is added as a dependency.
 * It enables:
 * - Component scanning for services, utilities, and other beans
 * - JPA repository scanning
 * - Entity scanning for JPA entities
 * - Configuration properties binding
 * 
 * No manual configuration needed in the consuming service.
 */
@AutoConfiguration
@ComponentScan(basePackages = "com.pranav.authcore")
@EnableJpaRepositories(basePackages = "com.pranav.authcore.repository")
@EntityScan(basePackages = "com.pranav.authcore.entity")
@EnableConfigurationProperties(AuthCoreProperties.class)
public class AuthCoreAutoConfiguration {
    
    @Bean
    public ObjectMapper objectMapper() {
        return new ObjectMapper();
    }
}
