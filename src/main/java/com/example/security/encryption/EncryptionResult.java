package com.example.security.encryption;

public class EncryptionResult {
    private String encryptedText;
    private String encryptionKey;

    void setEncryptedText(String encryptedText) {
        this.encryptedText = encryptedText;
    }

    void setEncryptionKey(String encryptionKey) {
        this.encryptionKey = encryptionKey;
    }

    public String getEncryptedText() {
        return encryptedText;
    }

    public String getEncryptionKey() {
        return encryptionKey;
    }

    @Override
    public String toString() {
        return "EncryptionResult [encryptedText=" + encryptedText + ", encryptionKey=" + encryptionKey + "]";
    }
}
