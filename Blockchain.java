package com.securecomms.blockchain;

import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * Blockchain — ordered, append-only ledger of communication events.
 *
 * <p>Thread-safe singleton (Spring {@code @Component} with synchronised
 * mutations). Each message sent, received, or verified appends a new
 * {@link Block} whose payload is a JSON digest of the event, ensuring:
 * <ul>
 *   <li>Non-repudiation — sender cannot deny sending a message</li>
 *   <li>Integrity — any modification breaks the hash chain</li>
 *   <li>Auditability — full communication history is publicly verifiable</li>
 * </ul>
 * </p>
 */
@Slf4j
@Component
public class Blockchain {

    @Value("${app.blockchain.difficulty:3}")
    private int difficulty;

    @Value("${app.blockchain.genesis-data:SecureComms Genesis Block v1.0}")
    private String genesisData;

    private final List<Block> chain = new ArrayList<>();

    /** Initialise with the genesis block on first use. */
    private synchronized void ensureGenesis() {
        if (chain.isEmpty()) {
            Block genesis = new Block(0, genesisData, "0".repeat(64));
            genesis.mineBlock(difficulty);
            chain.add(genesis);
            log.info("Genesis block created: {}", genesis);
        }
    }

    /**
     * Append a new block containing the given data payload.
     *
     * @param data JSON string describing the communication event
     * @return the newly mined block
     */
    public synchronized Block addBlock(String data) {
        ensureGenesis();
        Block previous = chain.get(chain.size() - 1);
        Block block    = new Block(chain.size(), data, previous.getHash());
        block.mineBlock(difficulty);
        chain.add(block);
        log.debug("Block #{} added — hash={}", block.getIndex(), block.getHash().substring(0, 12));
        return block;
    }

    /**
     * Validate the entire chain.
     *
     * <p>Checks that:
     * <ol>
     *   <li>Each block's stored hash matches a re-computation</li>
     *   <li>Each block's {@code previousHash} matches the prior block's hash</li>
     *   <li>Each hash satisfies the PoW difficulty target</li>
     * </ol>
     * </p>
     *
     * @return {@link ValidationResult} with {@code valid} flag and detail message
     */
    public synchronized ValidationResult validate() {
        ensureGenesis();
        String target = "0".repeat(difficulty);

        for (int i = 1; i < chain.size(); i++) {
            Block current  = chain.get(i);
            Block previous = chain.get(i - 1);

            if (!current.isValid()) {
                return new ValidationResult(false,
                    "Block #" + i + " hash mismatch — block was tampered!");
            }
            if (!current.getPreviousHash().equals(previous.getHash())) {
                return new ValidationResult(false,
                    "Block #" + i + " previous-hash linkage broken!");
            }
            if (!current.getHash().startsWith(target)) {
                return new ValidationResult(false,
                    "Block #" + i + " does not satisfy PoW difficulty " + difficulty);
            }
        }
        return new ValidationResult(true,
            "Chain valid — " + chain.size() + " blocks verified.");
    }

    /** @return immutable view of the chain */
    public List<Block> getChain() {
        ensureGenesis();
        return Collections.unmodifiableList(chain);
    }

    public int size() {
        ensureGenesis();
        return chain.size();
    }

    public int getDifficulty() { return difficulty; }

    // ── Inner result class ─────────────────────────────────────────────────

    public record ValidationResult(boolean valid, String message) {}
}