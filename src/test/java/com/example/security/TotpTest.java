package com.example.security;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

import java.io.InputStream;
import java.util.List;
import java.util.Scanner;

import org.apache.commons.lang3.StringUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class TotpTest {
    private static final Logger logger = LogManager.getLogger(TotpTest.class);
    

    public void validationTest(){
        // User info needed after logon , provider can be universal (MTO) or app specific (ALIA@MTO)
        String userId = "admin@example.com";
        String provider = "ExampleCompany";

        TotpCredentialService tcs = TotpCredentialService.getInstance();
        final TotpCredential cred = tcs.createCredential(userId, provider);

        assertEquals(userId, cred.getUserId());
        assertEquals(provider, cred.getProvider());
        assertNotNull(cred.getSecret());
        assertEquals(cred.getSecret().length(), 24);
        assertEquals(cred.getScratchCodes().size(), 5);

        logger.info("User [{}]", cred.getUserId());
        logger.info("Provider [{}]", cred.getProvider());
        logger.info("Secret is [{}]", cred.getSecret());
        logger.info("=========================================");
        logger.info("Encryption key is [{}]", cred.getEncryptionKey());
        logger.info("Encrypted Secret is [{}]", cred.getEncrytedSecret());

        final List<Integer> scratchCodes = cred.getScratchCodes();

        for (Integer i : scratchCodes) {
            if (!tcs.validateScratchCode(i)) {
                throw new IllegalArgumentException("An invalid code has been generated: this is an application bug.");
            }
            logger.info("Scratch code: [{}]", i);
        }

        try {
            TotpQRCodeService qrService = new TotpQRCodeService();
            qrService.generateQRCodeImageToFile(cred, "./src/main/resources/qrImage", "testQR.png");
            logger.info("QRCode generated");
        } catch (Exception e) {
            logger.error("QRCode generation failed");
            e.printStackTrace();
        }

        // User interactive mode: input passcode
        InputStream is = System.in;
        Scanner keyboard = new Scanner(is);
        boolean isValid = false;
        while (isValid == false){
            System.out.println("Please enter passcode");
            String input = keyboard.next();
            // String passcode = String.valueOf(input);

            while (!StringUtils.isNumeric(input) || input.length() != 6) {
                System.out.println("Passcode must be Numeric and 6 digit long");
                input = keyboard.next();
            }

            isValid = TotpPasscodeValidation.isPasscodeValid(cred.getEncrytedSecret(), cred.getEncryptionKey(), input);
            if(!isValid) {
                System.out.println("Passcode invalid, Please try again.");
            }
        }

        keyboard.close();

    }

    public static void main(String[] args) {

        TotpTest obj = new TotpTest();
        obj.validationTest();

    }
}
