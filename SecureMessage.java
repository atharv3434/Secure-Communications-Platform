package com.securecomms.model;

import jakarta.persistence.*;
import lombok.*;
import java.time.LocalDateTime;

/**
 * SecureMessage — a single end-to-end encrypted communication record.
 *
 * <p>The server stores only the ciphertext — it can never read the plaintext.
 * The {@code blockHash} links this message to its blockchain entry, providing
 * a tamper-evident audit trail.</p>
 *
 * <p>Fields:</p>
 * <ul>
 *   <li>{@code encryptedContent} — AES-256-GCM ciphertext (Base64)</li>
 *   <li>{@code iv} — GCM initialisation vector (Base64)</li>
 *   <li>{@code encryptedKey} — RSA-wrapped AES session key (Base64)</li>
 *   <li>{@code signature} — ECDSA signature of SHA-256(ciphertext) (Base64)</li>
 *   <li>{@code contentHash} — SHA-256 of ciphertext for blockchain indexing</li>
 *   <li>{@code blockHash} — hash of the blockchain block that records this message</li>
 *   <li>{@code blockIndex} — position in the blockchain</li>
 *   <li>{@code verified} — true once the recipient has verified the signature</li>
 * </ul>
 */
@Entity
@Table(name = "secure_messages")
@Getter @Setter @NoArgsConstructor @AllArgsConstructor @Builder
public class SecureMessage {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "sender_id", nullable = false)
    private User sender;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "recipient_id", nullable = false)
    private User recipient;

    // ── Encrypted payload ──────────────────────────────────────────────────
    @Column(columnDefinition = "TEXT", nullable = false)
    private String encryptedContent;  // AES-256-GCM ciphertext (Base64)

    @Column(nullable = false, length = 50)
    private String iv;                // GCM nonce (Base64)

    @Column(columnDefinition = "TEXT", nullable = false)
    private String encryptedKey;      // RSA-wrapped AES key for recipient

    @Column(columnDefinition = "TEXT")
    private String encryptedKeySender; // RSA-wrapped AES key copy for sender (read-own)

    // ── Authentication ─────────────────────────────────────────────────────
    @Column(columnDefinition = "TEXT")
    private String signature;         // ECDSA over SHA-256(ciphertext)

    @Column(nullable = false, length = 64)
    private String contentHash;       // SHA-256(ciphertext) hex

    // ── Blockchain reference ───────────────────────────────────────────────
    @Column(length = 64)
    private String blockHash;

    @Column
    private Integer blockIndex;

    // ── Metadata ──────────────────────────────────────────────────────────
    @Column(nullable = false)
    private LocalDateTime sentAt = LocalDateTime.now();

    @Column
    private LocalDateTime readAt;

    private boolean verified = false;
    private boolean read     = false;

    @Column(length = 100)
    private String subject;
}