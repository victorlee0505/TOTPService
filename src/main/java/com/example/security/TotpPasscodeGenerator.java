package com.example.security;

import com.example.security.constants.TotpConstant;

import org.jboss.aerogear.security.otp.Totp;
import org.jboss.aerogear.security.otp.api.Clock;

public class TotpPasscodeGenerator {

    private String encryptionKey;
    private String encryptedSecret;
    private int timeStep;

    public TotpPasscodeGenerator(String encryptedSecret, String encryptionKey, int timeStep) {
        this.encryptionKey = encryptionKey;
        this.encryptedSecret = encryptedSecret;
        this.timeStep = timeStep;
    }

    public TotpPasscodeGenerator(String encryptedSecret, String encryptionKey) {
        this(encryptedSecret, encryptionKey, TotpConstant.TOTP_DEFAULT_TIME_STEP);
    }

    public String getPasscode() {

        String secret = TotpPasscodeValidation.decrpytSecretKey(this.encryptedSecret, this.encryptionKey);

        Clock clock = new Clock(timeStep);

        Totp totp = new Totp(secret, clock);

        return totp.now();
    }

}
