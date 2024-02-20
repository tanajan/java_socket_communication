import java.io.Serial;
import java.io.Serializable;

public class Message implements Serializable {
    @Serial
    private static final long serialVersionUID = 1L;

    private final String encryptedContent;
    private final String timestamp;
    private final byte[] signature;
    private final String recipientUserId;
    private final String senderUserId; // Field for sender's user ID

    public Message(String encryptedContent, String timestamp, byte[] signature, String recipientUserId, String senderUserId) {
        this.encryptedContent = encryptedContent;
        this.timestamp = timestamp;
        this.signature = signature;
        this.recipientUserId = recipientUserId;
        this.senderUserId = senderUserId;
    }

    // Getters
    public String getEncryptedContent() {
        return encryptedContent;
    }

    public String getTimestamp() {
        return timestamp;
    }

    public byte[] getSignature() {
        return signature;
    }

    public String getRecipientUserId() {
        return recipientUserId;
    }

    public String getSenderUserId() {
        return senderUserId;
    }

    // You might also add setters or other methods as needed for your application logic
}
