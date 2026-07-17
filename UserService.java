package com.securecomms.service;

import com.securecomms.crypto.CryptoService;
import com.securecomms.model.User;
import com.securecomms.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.userdetails.*;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import java.security.KeyPair;
import java.util.List;
import java.util.Optional;

/**
 * UserService — manages user lifecycle and cryptographic key provisioning.
 *
 * <p>On registration, two key pairs are generated automatically:
 * <ol>
 *   <li>RSA-2048 for wrapping AES session keys (encryption/decryption)</li>
 *   <li>ECDSA P-256 for signing and verifying message authenticity</li>
 * </ol>
 * Keys are stored in the database; in production the private keys would
 * be delivered to the client and never stored server-side.</p>
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class UserService implements UserDetailsService {

    private final UserRepository  userRepo;
    private final CryptoService   cryptoService;
    private final PasswordEncoder passwordEncoder;

    /**
     * Register a new user and generate their cryptographic key pairs.
     */
    @Transactional
    public User register(String username, String password, String email) {
        if (userRepo.existsByUsername(username)) {
            throw new IllegalArgumentException("Username already taken: " + username);
        }
        if (userRepo.existsByEmail(email)) {
            throw new IllegalArgumentException("Email already registered: " + email);
        }

        try {
            // Generate RSA-2048 key pair
            KeyPair rsaKp = cryptoService.generateRsaKeyPair();
            // Generate ECDSA P-256 key pair
            KeyPair ecKp  = cryptoService.generateEcKeyPair();

            User user = User.builder()
                .username(username)
                .passwordHash(passwordEncoder.encode(password))
                .email(email)
                .rsaPublicKey(cryptoService.encodePublicKey(rsaKp.getPublic()))
                .rsaPrivateKey(cryptoService.encodePrivateKey(rsaKp.getPrivate()))
                .ecPublicKey(cryptoService.encodePublicKey(ecKp.getPublic()))
                .ecPrivateKey(cryptoService.encodePrivateKey(ecKp.getPrivate()))
                .role("ROLE_USER")
                .build();

            User saved = userRepo.save(user);
            log.info("User '{}' registered with RSA-2048 + ECDSA-P256 keys", username);
            return saved;

        } catch (Exception e) {
            throw new RuntimeException("Key generation failed during registration", e);
        }
    }

    public Optional<User> findByUsername(String username) {
        return userRepo.findByUsername(username);
    }

    public Optional<User> findById(Long id) {
        return userRepo.findById(id);
    }

    public List<User> getAllOtherUsers(String currentUsername) {
        return userRepo.findAllByUsernameNot(currentUsername);
    }

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        return userRepo.findByUsername(username)
            .map(u -> org.springframework.security.core.userdetails.User
                .withUsername(u.getUsername())
                .password(u.getPasswordHash())
                .roles(u.getRole().replace("ROLE_", ""))
                .build())
            .orElseThrow(() -> new UsernameNotFoundException("User not found: " + username));
    }
}