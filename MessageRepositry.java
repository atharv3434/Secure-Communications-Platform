package com.securecomms.repository;

import com.securecomms.model.SecureMessage;
import com.securecomms.model.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;
import java.util.List;

@Repository
public interface MessageRepository extends JpaRepository<SecureMessage, Long> {

    List<SecureMessage> findByRecipientOrderBySentAtDesc(User recipient);

    List<SecureMessage> findBySenderOrderBySentAtDesc(User sender);

    @Query("""
        SELECT m FROM SecureMessage m
        WHERE (m.sender = :a AND m.recipient = :b)
           OR (m.sender = :b AND m.recipient = :a)
        ORDER BY m.sentAt ASC
    """)
    List<SecureMessage> findConversation(User a, User b);

    long countByRecipientAndReadFalse(User recipient);

    List<SecureMessage> findByBlockIndex(int blockIndex);
}