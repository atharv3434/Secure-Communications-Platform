package com.securecomms.model;

import jakarta.persistence.*;
import lombok.*;
import java.time.LocalDateTime;

/**
 * User — registered participant in the secure communications network.
 *
 * <p>Each user holds two key pairs:
 * <ul>
 *   <li><b>RSA-2048</b> — for wrapping/unwrapping AES session keys</li>
 *   <li><b>ECDSA P-256</b> — for signing and verifying messages</li>
 * </ul>
 * Private keys are stored server-side in this prototype. In production,
 * private keys would remain exclusively on the client device (HSM / secure
 * enclave) and never leave it.</p>
 */
@Entity
@Table(name = "users")
@Getter @Setter @NoArgsConstructor @AllArgsConstructor @Builder
public class User {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(unique = true, nullable = false, length = 50)
    private String username;

    @Column(nullable = false)
    private String passwordHash;

    @Column(nullable = false, length = 100)
    private String email;

    @Column(columnDefinition = "TEXT")
    private String rsaPublicKey;    // Base64 DER

    @Column(columnDefinition = "TEXT")
    private String rsaPrivateKey;   // Base64 DER (prototype only)

    @Column(columnDefinition = "TEXT")
    private String ecPublicKey;     // Base64 DER (for ECDSA)

    @Column(columnDefinition = "TEXT")
    private String ecPrivateKey;    // Base64 DER (prototype only)

    @Column(nullable = false)
    private String role = "ROLE_USER";

    @Column(nullable = false)
    private LocalDateTime createdAt = LocalDateTime.now();

    private LocalDateTime lastLogin;
}