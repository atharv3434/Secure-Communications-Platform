package com.securecomms;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import java.security.Security;

/**
 * SecureCommsApplication — Entry point.
 *
 * Registers Bouncy Castle as a JCE security provider on startup so that
 * all cryptographic operations (RSA-2048, AES-256-GCM, ECDSA) are available
 * throughout the application context.
 */
@SpringBootApplication
public class SecureCommsApplication {

    static {
        // Register BouncyCastle provider before Spring context initialises
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    public static void main(String[] args) {
        SpringApplication.run(SecureCommsApplication.class, args);
    }
}