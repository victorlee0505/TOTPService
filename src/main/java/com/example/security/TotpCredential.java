package com.example.security;

import java.util.ArrayList;
import java.util.List;

public class TotpCredential {

    private String userId;
    private String provider;
    private String secret;
    private String encryptionKey;
    private String encrytedSecret;
    private List<Integer> scratchCodes;

    public TotpCredential() {
    }

    public TotpCredential(String userId, String provider, String secret, String encryptionKey, String encrytedSecret,
            List<Integer> scratchCodes) {
        this.userId = userId;
        this.provider = provider;
        this.secret = secret;
        this.encryptionKey = encryptionKey;
        this.encrytedSecret = encrytedSecret;
        this.scratchCodes = scratchCodes;
    }

    public String getUserId() {
        return userId;
    }

    public void setUserId(String userId) {
        this.userId = userId;
    }

    public String getProvider() {
        return provider;
    }

    public void setProvider(String provider) {
        this.provider = provider;
    }

    public String getSecret() {
        return secret;
    }

    public String getEncryptionKey() {
        return encryptionKey;
    }

    public String getEncrytedSecret() {
        return encrytedSecret;
    }

    public List<Integer> getScratchCodes() {
        if (this.scratchCodes == null) {
            return new ArrayList<Integer>();
        }
        return scratchCodes;
    }

}
