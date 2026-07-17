package com.securecomms.blockchain;

import lombok.Getter;
import lombok.Setter;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Instant;
import java.util.HexFormat;

/**
 * Block — one link in the secure-communications blockchain.
 *
 * <p>Each block records a hashed digest of a message event (send, receive,
 * verify) and chains it to the previous block via {@code previousHash}.
 * The SHA-256 hash of (index + timestamp + data + previousHash + nonce)
 * must start with {@code difficulty} leading zeros — proof-of-work.</p>
 *
 * <p>Tamper detection: changing any field in any block invalidates every
 * subsequent block's {@code previousHash} linkage.</p>
 */
@Getter
@Setter
public class Block {

    private final int    index;
    private final long   timestamp;
    private final String data;           // JSON payload (message hash, sender, recipient)
    private final String previousHash;
    private       int    nonce;
    private       String hash;

    public Block(int index, String data, String previousHash) {
        this.index        = index;
        this.timestamp    = Instant.now().getEpochSecond();
        this.data         = data;
        this.previousHash = previousHash;
        this.nonce        = 0;
        this.hash         = computeHash();
    }

    /**
     * SHA-256 over all immutable fields plus nonce.
     * Called after every nonce increment during mining.
     */
    public String computeHash() {
        String input = index + timestamp + data + previousHash + nonce;
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] bytes = digest.digest(input.getBytes(StandardCharsets.UTF_8));
            return HexFormat.of().formatHex(bytes);
        } catch (Exception e) {
            throw new RuntimeException("SHA-256 not available", e);
        }
    }

    /**
     * Proof-of-Work: increment nonce until hash starts with
     * {@code difficulty} leading zero characters.
     */
    public void mineBlock(int difficulty) {
        String target = "0".repeat(difficulty);
        while (!hash.startsWith(target)) {
            nonce++;
            hash = computeHash();
        }
    }

    /** @return true if stored hash matches a freshly computed hash */
    public boolean isValid() {
        return hash.equals(computeHash());
    }

    @Override
    public String toString() {
        return String.format(
            "Block{index=%d, hash='%s...', prev='%s...', nonce=%d}",
            index,
            hash.substring(0, Math.min(12, hash.length())),
            previousHash.substring(0, Math.min(12, previousHash.length())),
            nonce
        );
    }
}