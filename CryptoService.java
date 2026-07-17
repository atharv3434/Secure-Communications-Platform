package com.securecomms.crypto;

import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import javax.crypto.*;
import javax.crypto.spec.*;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.*;
import java.util.Base64;

/**
 * CryptoService — Central cryptographic operations.
 *
 * <p>Provides:</p>
 * <ul>
 *   <li><b>RSA-2048 OAEP</b>    — asymmetric key wrapping for AES session keys</li>
 *   <li><b>AES-256-GCM</b>      — authenticated symmetric encryption of message payloads</li>
 *   <li><b>ECDSA (P-256)</b>    — digital signatures for message authentication</li>
 *   <li><b>SHA-256</b>           — content hashing for blockchain payloads</li>
 * </ul>
 *
 * <p>Encryption flow for a message M from Alice to Bob:</p>
 * <pre>
 *   1. Generate random AES-256 session key K
 *   2. Encrypt M with K under AES-256-GCM  → ciphertext C
 *   3. Wrap K with Bob's RSA public key    → encryptedKey EK
 *   4. Sign SHA-256(C) with Alice's EC key → signature S
 *   5. Send { EK, C, nonce, S, alicePubKey }
 *
 *   Bob decrypts:
 *   1. Unwrap EK with his RSA private key  → K
 *   2. Verify S against C using alicePubKey
 *   3. Decrypt C with K                    → M
 * </pre>
 */
@Slf4j
@Service
public class CryptoService {

    private static final String RSA_ALGO  = "RSA/ECB/OAEPWithSHA-256AndMGF1Padding";
    private static final String AES_ALGO  = "AES/GCM/NoPadding";
    private static final String ECDSA_ALGO = "SHA256withECDSA";
    private static final int    GCM_TAG_BITS  = 128;
    private static final int    GCM_IV_BYTES  = 12;
    private static final int    AES_KEY_BITS  = 256;

    // ── RSA Key Generation ─────────────────────────────────────────────────

    /**
     * Generate a 2048-bit RSA key pair for asymmetric key wrapping.
     */
    public KeyPair generateRsaKeyPair() throws GeneralSecurityException {
        KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA", "BC");
        gen.initialize(2048, new SecureRandom());
        return gen.generateKeyPair();
    }

    /**
     * Serialise a public key to Base64-encoded DER (X.509 SubjectPublicKeyInfo).
     */
    public String encodePublicKey(PublicKey key) {
        return Base64.getEncoder().encodeToString(key.getEncoded());
    }

    /**
     * Serialise a private key to Base64-encoded DER (PKCS#8).
     */
    public String encodePrivateKey(PrivateKey key) {
        return Base64.getEncoder().encodeToString(key.getEncoded());
    }

    /**
     * Reconstruct an RSA public key from Base64-encoded DER.
     */
    public PublicKey decodeRsaPublicKey(String b64) throws GeneralSecurityException {
        byte[] bytes = Base64.getDecoder().decode(b64);
        return KeyFactory.getInstance("RSA", "BC")
                         .generatePublic(new X509EncodedKeySpec(bytes));
    }

    /**
     * Reconstruct an RSA private key from Base64-encoded DER.
     */
    public PrivateKey decodeRsaPrivateKey(String b64) throws GeneralSecurityException {
        byte[] bytes = Base64.getDecoder().decode(b64);
        return KeyFactory.getInstance("RSA", "BC")
                         .generatePrivate(new PKCS8EncodedKeySpec(bytes));
    }

    // ── ECDSA Key Generation ───────────────────────────────────────────────

    /**
     * Generate a P-256 (secp256r1) ECDSA key pair for message signing.
     */
    public KeyPair generateEcKeyPair() throws GeneralSecurityException {
        KeyPairGenerator gen = KeyPairGenerator.getInstance("EC", "BC");
        gen.initialize(new ECGenParameterSpec("P-256"), new SecureRandom());
        return gen.generateKeyPair();
    }

    public PublicKey decodeEcPublicKey(String b64) throws GeneralSecurityException {
        byte[] bytes = Base64.getDecoder().decode(b64);
        return KeyFactory.getInstance("EC", "BC")
                         .generatePublic(new X509EncodedKeySpec(bytes));
    }

    public PrivateKey decodeEcPrivateKey(String b64) throws GeneralSecurityException {
        byte[] bytes = Base64.getDecoder().decode(b64);
        return KeyFactory.getInstance("EC", "BC")
                         .generatePrivate(new PKCS8EncodedKeySpec(bytes));
    }

    // ── AES-256-GCM Encryption ─────────────────────────────────────────────

    /**
     * Encrypt a plaintext message with AES-256-GCM.
     *
     * @param plaintext UTF-8 message string
     * @param keyBytes  32-byte AES key
     * @return {@link EncryptedPayload} containing Base64 ciphertext + IV
     */
    public EncryptedPayload encryptAesGcm(String plaintext, byte[] keyBytes)
            throws GeneralSecurityException {
        SecretKey key = new SecretKeySpec(keyBytes, "AES");
        byte[]    iv  = new byte[GCM_IV_BYTES];
        new SecureRandom().nextBytes(iv);

        Cipher cipher = Cipher.getInstance(AES_ALGO, "BC");
        cipher.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(GCM_TAG_BITS, iv));

        byte[] cipherBytes = cipher.doFinal(plaintext.getBytes(StandardCharsets.UTF_8));

        return new EncryptedPayload(
            Base64.getEncoder().encodeToString(cipherBytes),
            Base64.getEncoder().encodeToString(iv)
        );
    }

    /**
     * Decrypt an AES-256-GCM payload.
     *
     * @param payload  encrypted payload (ciphertext + IV in Base64)
     * @param keyBytes 32-byte AES key
     * @return plaintext UTF-8 string
     */
    public String decryptAesGcm(EncryptedPayload payload, byte[] keyBytes)
            throws GeneralSecurityException {
        SecretKey key       = new SecretKeySpec(keyBytes, "AES");
        byte[]    iv        = Base64.getDecoder().decode(payload.iv());
        byte[]    ciphered  = Base64.getDecoder().decode(payload.ciphertext());

        Cipher cipher = Cipher.getInstance(AES_ALGO, "BC");
        cipher.init(Cipher.DECRYPT_MODE, key, new GCMParameterSpec(GCM_TAG_BITS, iv));
        byte[] plain = cipher.doFinal(ciphered);
        return new String(plain, StandardCharsets.UTF_8);
    }

    // ── RSA Key Wrapping ───────────────────────────────────────────────────

    /**
     * Generate a random 256-bit AES session key.
     */
    public byte[] generateAesKey() throws GeneralSecurityException {
        KeyGenerator gen = KeyGenerator.getInstance("AES", "BC");
        gen.init(AES_KEY_BITS, new SecureRandom());
        return gen.generateKey().getEncoded();
    }

    /**
     * Wrap (encrypt) an AES key with an RSA-2048 public key (OAEP-SHA256).
     *
     * @return Base64-encoded wrapped key
     */
    public String wrapAesKey(byte[] aesKey, PublicKey rsaPublic)
            throws GeneralSecurityException {
        Cipher cipher = Cipher.getInstance(RSA_ALGO, "BC");
        cipher.init(Cipher.ENCRYPT_MODE, rsaPublic);
        byte[] wrapped = cipher.doFinal(aesKey);
        return Base64.getEncoder().encodeToString(wrapped);
    }

    /**
     * Unwrap (decrypt) an AES key with an RSA-2048 private key.
     *
     * @return raw AES key bytes
     */
    public byte[] unwrapAesKey(String wrappedB64, PrivateKey rsaPrivate)
            throws GeneralSecurityException {
        Cipher cipher = Cipher.getInstance(RSA_ALGO, "BC");
        cipher.init(Cipher.DECRYPT_MODE, rsaPrivate);
        return cipher.doFinal(Base64.getDecoder().decode(wrappedB64));
    }

    // ── ECDSA Signing ──────────────────────────────────────────────────────

    /**
     * Sign data (typically a message hash) with ECDSA (P-256, SHA-256).
     *
     * @return Base64-encoded DER signature
     */
    public String sign(byte[] data, PrivateKey ecPrivate)
            throws GeneralSecurityException {
        Signature signer = Signature.getInstance(ECDSA_ALGO, "BC");
        signer.initSign(ecPrivate);
        signer.update(data);
        return Base64.getEncoder().encodeToString(signer.sign());
    }

    /**
     * Verify an ECDSA signature.
     *
     * @return true if the signature is valid
     */
    public boolean verify(byte[] data, String signatureB64, PublicKey ecPublic)
            throws GeneralSecurityException {
        Signature verifier = Signature.getInstance(ECDSA_ALGO, "BC");
        verifier.initVerify(ecPublic);
        verifier.update(data);
        return verifier.verify(Base64.getDecoder().decode(signatureB64));
    }

    // ── Hashing ────────────────────────────────────────────────────────────

    /**
     * SHA-256 hash of a string — used for blockchain payloads.
     *
     * @return hex-encoded hash
     */
    public String sha256Hex(String input) {
        try {
            MessageDigest md    = MessageDigest.getInstance("SHA-256", "BC");
            byte[]        bytes = md.digest(input.getBytes(StandardCharsets.UTF_8));
            StringBuilder sb    = new StringBuilder(bytes.length * 2);
            for (byte b : bytes) sb.append(String.format("%02x", b));
            return sb.toString();
        } catch (Exception e) {
            throw new RuntimeException("SHA-256 unavailable", e);
        }
    }

    // ── Value records ──────────────────────────────────────────────────────

    /** Holds AES-GCM ciphertext and IV, both Base64-encoded. */
    public record EncryptedPayload(String ciphertext, String iv) {}
}