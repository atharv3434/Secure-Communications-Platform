package com.securecomms.service;

import com.securecomms.blockchain.Block;
import com.securecomms.blockchain.Blockchain;
import com.securecomms.crypto.CryptoService;
import com.securecomms.model.SecureMessage;
import com.securecomms.model.User;
import com.securecomms.repository.MessageRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.time.LocalDateTime;
import java.util.List;

/**
 * MessageService — orchestrates the full secure-messaging pipeline.
 *
 * <h3>Send flow</h3>
 * <ol>
 *   <li>Generate a random AES-256 session key K</li>
 *   <li>Encrypt plaintext with K (AES-256-GCM) → {ciphertext, IV}</li>
 *   <li>Wrap K with recipient's RSA public key → encryptedKey</li>
 *   <li>Wrap K with sender's RSA public key   → encryptedKeySender (for read-own)</li>
 *   <li>Sign SHA-256(ciphertext) with sender's EC private key → signature</li>
 *   <li>Record event on blockchain → blockHash, blockIndex</li>
 *   <li>Persist {@link SecureMessage} to database</li>
 * </ol>
 *
 * <h3>Read flow (recipient)</h3>
 * <ol>
 *   <li>Unwrap encryptedKey with recipient's RSA private key → K</li>
 *   <li>Decrypt ciphertext with K → plaintext</li>
 *   <li>Verify signature against SHA-256(ciphertext) using sender's EC public key</li>
 * </ol>
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class MessageService {

    private final MessageRepository messageRepo;
    private final CryptoService     cryptoService;
    private final Blockchain        blockchain;

    // ── Send ──────────────────────────────────────────────────────────────────

    /**
     * Encrypt and send a message from sender to recipient.
     *
     * @param plaintext the message body
     * @param subject   optional subject line
     * @param sender    authenticated sender User
     * @param recipient target User
     * @return the persisted {@link SecureMessage} (ciphertext only — no plaintext stored)
     */
    @Transactional
    public SecureMessage send(String plaintext, String subject,
                               User sender, User recipient) throws Exception {

        // 1. Generate AES-256 session key
        byte[] aesKey = cryptoService.generateAesKey();

        // 2. Encrypt message with AES-256-GCM
        CryptoService.EncryptedPayload encrypted = cryptoService.encryptAesGcm(plaintext, aesKey);

        // 3. Wrap AES key for recipient (RSA-OAEP)
        PublicKey recipientRsaPub = cryptoService.decodeRsaPublicKey(recipient.getRsaPublicKey());
        String encryptedKey       = cryptoService.wrapAesKey(aesKey, recipientRsaPub);

        // 4. Wrap AES key for sender (read own messages)
        PublicKey senderRsaPub   = cryptoService.decodeRsaPublicKey(sender.getRsaPublicKey());
        String encryptedKeySender = cryptoService.wrapAesKey(aesKey, senderRsaPub);

        // 5. Sign ciphertext hash with sender's EC private key
        String contentHash   = cryptoService.sha256Hex(encrypted.ciphertext());
        PrivateKey senderEc  = cryptoService.decodeEcPrivateKey(sender.getEcPrivateKey());
        String signature     = cryptoService.sign(
            hexToBytes(contentHash), senderEc);

        // 6. Record on blockchain
        String blockData = buildBlockPayload(sender.getUsername(),
                                             recipient.getUsername(), contentHash);
        Block block = blockchain.addBlock(blockData);

        // 7. Persist
        SecureMessage msg = SecureMessage.builder()
            .sender(sender)
            .recipient(recipient)
            .encryptedContent(encrypted.ciphertext())
            .iv(encrypted.iv())
            .encryptedKey(encryptedKey)
            .encryptedKeySender(encryptedKeySender)
            .signature(signature)
            .contentHash(contentHash)
            .blockHash(block.getHash())
            .blockIndex(block.getIndex())
            .subject(subject)
            .sentAt(LocalDateTime.now())
            .build();

        SecureMessage saved = messageRepo.save(msg);
        log.info("Message #{} from '{}' to '{}' encrypted and added to block #{}",
                 saved.getId(), sender.getUsername(), recipient.getUsername(), block.getIndex());
        return saved;
    }

    // ── Decrypt ───────────────────────────────────────────────────────────────

    /**
     * Decrypt and verify a received message.
     *
     * @param messageId ID of the message to decrypt
     * @param reader    the User requesting decryption (must be sender or recipient)
     * @return {@link DecryptResult} containing plaintext and verification status
     */
    @Transactional
    public DecryptResult decrypt(Long messageId, User reader) throws Exception {
        SecureMessage msg = messageRepo.findById(messageId)
            .orElseThrow(() -> new IllegalArgumentException("Message not found: " + messageId));

        boolean isRecipient = msg.getRecipient().getId().equals(reader.getId());
        boolean isSender    = msg.getSender().getId().equals(reader.getId());

        if (!isRecipient && !isSender) {
            throw new SecurityException("Access denied — not sender or recipient");
        }

        // Unwrap AES key with reader's RSA private key
        PrivateKey rsaPrivate = cryptoService.decodeRsaPrivateKey(reader.getRsaPrivateKey());
        String     wrappedKey = isRecipient ? msg.getEncryptedKey() : msg.getEncryptedKeySender();
        byte[] aesKey = cryptoService.unwrapAesKey(wrappedKey, rsaPrivate);

        // Decrypt ciphertext
        CryptoService.EncryptedPayload payload =
            new CryptoService.EncryptedPayload(msg.getEncryptedContent(), msg.getIv());
        String plaintext = cryptoService.decryptAesGcm(payload, aesKey);

        // Verify signature using sender's EC public key
        PublicKey senderEc = cryptoService.decodeEcPublicKey(msg.getSender().getEcPublicKey());
        boolean sigOk = cryptoService.verify(
            hexToBytes(msg.getContentHash()), msg.getSignature(), senderEc);

        // Verify blockchain integrity
        Blockchain.ValidationResult chainOk = blockchain.validate();

        // Mark as read
        if (isRecipient && !msg.isRead()) {
            msg.setRead(true);
            msg.setReadAt(LocalDateTime.now());
            msg.setVerified(sigOk);
            messageRepo.save(msg);
        }

        return new DecryptResult(plaintext, sigOk, chainOk.valid(), msg);
    }

    // ── Queries ───────────────────────────────────────────────────────────────

    public List<SecureMessage> getInbox(User user) {
        return messageRepo.findByRecipientOrderBySentAtDesc(user);
    }

    public List<SecureMessage> getSentMessages(User user) {
        return messageRepo.findBySenderOrderBySentAtDesc(user);
    }

    public List<SecureMessage> getConversation(User a, User b) {
        return messageRepo.findConversation(a, b);
    }

    public long getUnreadCount(User user) {
        return messageRepo.countByRecipientAndReadFalse(user);
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private String buildBlockPayload(String sender, String recipient, String hash) {
        return String.format(
            "{\"event\":\"MESSAGE\",\"sender\":\"%s\",\"recipient\":\"%s\"," +
            "\"contentHash\":\"%s\",\"timestamp\":%d}",
            sender, recipient, hash, System.currentTimeMillis()
        );
    }

    private byte[] hexToBytes(String hex) {
        int len = hex.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(hex.charAt(i), 16) << 4)
                                 + Character.digit(hex.charAt(i + 1), 16));
        }
        return data;
    }

    // ── Result record ─────────────────────────────────────────────────────────

    public record DecryptResult(
        String plaintext,
        boolean signatureValid,
        boolean blockchainValid,
        SecureMessage message
    ) {}
}