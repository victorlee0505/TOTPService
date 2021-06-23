package com.example.security;

import com.example.security.encryption.EncryptionService;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.jboss.aerogear.security.otp.Totp;

/**
 * from https://www.baeldung.com/spring-security-two-factor-authentication-with-soft-token
 */
public class TotpPasscodeValidation {
    
    private static final Logger logger = LogManager.getLogger(TotpPasscodeValidation.class);

    /**
     * Use encrpytedSecret from DB && Use encrpytion Key to get REAL secret that used by Passcode
     * @param encrpytedSecret
     * @param key
     * @param passcode
     * @return
     */
    public static Boolean isPasscodeValid(String encrpytedSecret, String encrpytionKey, String passcode) {

        String secret = decrpytSecretKey(encrpytedSecret, encrpytionKey);
        Totp totp = new Totp(secret);
        return totp.verify(passcode);
    }

    /**
     * decrytp a secret
     * @param buffer
     * @return
     */
    public static String decrpytSecretKey(String encrpytedSecret, String encrpytionKey) {

        EncryptionService encryptionService = new EncryptionService();
        String secret = encryptionService.decrypt(encrpytedSecret, encrpytionKey);

        return secret;
    }
}
