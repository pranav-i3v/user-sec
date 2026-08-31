package com.pranav.authcore.entity;

import jakarta.persistence.*;
import lombok.*;
import org.hibernate.annotations.CreationTimestamp;

import java.time.Instant;
import java.util.UUID;

@Entity
@Table(name = "permissions", schema = "sec", uniqueConstraints = {
    @UniqueConstraint(columnNames = {"path_pattern", "http_method"})
})
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class Permission {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    @Column(unique = true, length = 150)
    private String code;

    @Column(name = "path_pattern", nullable = false, length = 255)
    private String pathPattern;

    @Enumerated(EnumType.STRING)
    @Column(name = "http_method", nullable = false, length = 10)
    @Builder.Default
    private HttpMethod httpMethod = HttpMethod.ANY;

    @Column(columnDefinition = "TEXT")
    private String description;

    @CreationTimestamp
    @Column(nullable = false, updatable = false)
    private Instant createdAt;

    public enum HttpMethod {
        GET, POST, PUT, PATCH, DELETE, ANY
    }
}
