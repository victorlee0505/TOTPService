package com.example.security;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.util.List;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.junit.jupiter.api.Test;

public class TotpCredentialServiceTest {

    private static final Logger logger = LogManager.getLogger(TotpCredentialServiceTest.class);
    
    @Test
    public void createCredentials() {
        String userId = "admin";
        String provider = "google";

        TotpCredentialService ocs = TotpCredentialService.getInstance();

        final TotpCredential cred = ocs.createCredential(userId, provider);

        logger.info("User [{}]", cred.getUserId());
        logger.info("Provider [{}]", cred.getProvider());
        logger.info("Secret is [{}]", cred.getSecret());
        logger.info("EncryptionKey is [{}]", cred.getEncryptionKey());
        logger.info("EncrytedSecret is [{}]", cred.getEncrytedSecret());

        final List<Integer> scratchCodes = cred.getScratchCodes();

        for (Integer i : scratchCodes) {
            if (!ocs.validateScratchCode(i)) {
                throw new IllegalArgumentException("An invalid code has been generated: this is an application bug.");
            }
            logger.info("Scratch code: [{}]", i);
        }
    }

    @Test
    public void createCredentialsWithKey() {
        String userId = "admin";
        String provider = "google";
        String encryptionKey = "9RMj6zJ1uRehrRQBac4jHnZbSNPm+Q4dIaaajaqLdDo=";

        TotpCredentialService ocs = TotpCredentialService.getInstance();

        final TotpCredential cred = ocs.createCredential(userId, provider, encryptionKey);

        logger.info("User [{}]", cred.getUserId());
        logger.info("Provider [{}]", cred.getProvider());
        logger.info("Secret is [{}]", cred.getSecret());
        logger.info("EncryptionKey is [{}]", cred.getEncryptionKey());
        logger.info("EncrytedSecret is [{}]", cred.getEncrytedSecret());

        assertEquals(encryptionKey, cred.getEncryptionKey());

    }
    
}
