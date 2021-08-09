package com.example.security;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.junit.jupiter.api.Test;

public class TotpPasscodeTest {
    private static final Logger logger = LogManager.getLogger(TotpPasscodeTest.class);

    @Test
    public void passcodeDefault() {
        String userId = "somename";
        String provider = "someprovider";
        String encryptionKey = "kjvPYGE7Uj3oHyH2G5sEMhlbCvTsOQJgn8olsLEa5VE=";

        TotpCredentialService ocs = TotpCredentialService.getInstance();

        final TotpCredential cred = ocs.createCredential(userId, provider, encryptionKey);

        logger.info("User [{}]", cred.getUserId());
        logger.info("Provider [{}]", cred.getProvider());
        logger.info("Secret is [{}]", cred.getSecret());
        logger.info("EncryptionKey is [{}]", cred.getEncryptionKey());
        logger.info("EncrytedSecret is [{}]", cred.getEncrytedSecret());

        assertEquals(encryptionKey, cred.getEncryptionKey());

        TotpPasscodeGenerator totp;
        int failCount = 0;
        try {
            totp = new TotpPasscodeGenerator(cred.getEncrytedSecret(), cred.getEncryptionKey());

            String passcodeStr;

            passcodeStr = totp.getPasscode();

            logger.info("Current password: [{}]", passcodeStr);

            long start = System.currentTimeMillis();
            while (true) {
                long end = System.currentTimeMillis();
                if (end - start > 60000) {
                    break;
                }

                Thread.sleep(1000);
                boolean isValid = TotpPasscodeValidation.isPasscodeValid(cred.getEncrytedSecret(), encryptionKey, passcodeStr);

                logger.info("CurrentTime: [{}s] , PasscodeValid [{}]", (end - start) / 1000, isValid);

                if (!isValid) {
                    failCount++;
                }
            }
        } catch (InterruptedException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
        assertTrue(failCount > 0);

    }
}
