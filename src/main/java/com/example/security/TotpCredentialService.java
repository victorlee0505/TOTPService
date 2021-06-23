package com.example.security;

import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import com.example.security.encryption.EncryptionResult;
import com.example.security.encryption.EncryptionService;
import com.example.security.exceptions.TotpServiceException;

import org.apache.commons.codec.binary.Base32;
import org.apache.commons.lang3.StringUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * from https://github.com/wstrange/GoogleAuth
 */
public class TotpCredentialService {
    
    private static final Logger logger = LogManager.getLogger(TotpCredentialService.class);

    private static final String RANDOM_NUMBER_ALGORITHM = "SHA1PRNG";
    private static final String RANDOM_NUMBER_ALGORITHM_PROVIDER = "SUN";

    private static final int SECRET_BYTES = 15;
    private static final int SECRET_LENGTH = 24;
    private static final int SCRATCH_CODES = 5;
    private static final int SCRATCH_CODE_LENGTH = 8;
    private static final int BYTES_PER_SCRATCH_CODE = 4;
    private static final int SCRATCH_CODE_MODULUS = (int) Math.pow(10, SCRATCH_CODE_LENGTH);
    private static final int SCRATCH_CODE_INVALID = -1;

    private SecureRandom secureRandom;

    /**
     * class holder
     */
    private static class Loader {
        static final TotpCredentialService otpAuthenticator = new TotpCredentialService();
    }

    /**
     * Singleton
     * @return
     */
    public static TotpCredentialService getInstance() {
        return Loader.otpAuthenticator;
    }

    /**
     * Constructor: defined java.security.SecureRandomSecureRandom Algorithm & Algorithm provider
     */
    private TotpCredentialService() {
        logger.debug("OtpAuthenticator ---> ");
        try {
            this.secureRandom = SecureRandom.getInstance(RANDOM_NUMBER_ALGORITHM, RANDOM_NUMBER_ALGORITHM_PROVIDER);
        } catch (NoSuchAlgorithmException e) {
            throw new TotpServiceException(String.format(
                    "Could not initialise SecureRandom with the specified algorithm: %s", RANDOM_NUMBER_ALGORITHM), e);
        } catch (NoSuchProviderException e) {
            throw new TotpServiceException(
                    String.format("Could not initialise SecureRandom with the specified provider: %s", RANDOM_NUMBER_ALGORITHM_PROVIDER), e);
        }
        logger.debug(" <--- OtpAuthenticator");
    }

    /**
     * Generate TotpCredential where randomly generated secret and scatch codes provided
     * Recursively re-gen secret if secret.length abnormally long/short
     * @param userId
     * @param provider
     * @return
     */
    public TotpCredential createCredential(String userId, String provider, String ecryptionKey) {

        TotpCredential cred = generateCredential(userId, provider, ecryptionKey);

        if (cred.getSecret().length() != SECRET_LENGTH) {
            cred = createCredential(userId, provider, ecryptionKey);
        }
        return cred;
    }

    /**
     * Generate a psuedo TotpCredential without user/provider/encryptionKey
     * @return
     */
    public TotpCredential createCredential() {

        TotpCredential cred = generateCredential(null, null, null);

        if (cred.getSecret().length() != SECRET_LENGTH) {
            cred = createCredential(null, null, null);
        }
        return cred;
    }

    /**
     * Generate a psuedo TotpCredential without user/provider with encryptionKey
     * @return
     */
    public TotpCredential createCredential(String ecryptionKey) {

        TotpCredential cred = generateCredential(null, null, ecryptionKey);

        if (cred.getSecret().length() != SECRET_LENGTH) {
            cred = createCredential(null, null, ecryptionKey);
        }
        return cred;
    }

        /**
     * Generate a psuedo TotpCredential without user/provider with encryptionKey
     * @return
     */
    public TotpCredential createCredential(String userId, String provider) {

        TotpCredential cred = generateCredential(userId, provider, null);

        if (cred.getSecret().length() != SECRET_LENGTH) {
            cred = createCredential(userId, provider, null);
        }
        return cred;
    }

    /**
     * return a valid TotpCredential object
     * @param userId
     * @param provider
     * @return
     */
    private TotpCredential generateCredential(String userId, String provider, String ecryptionKey) {
        TotpCredential cred = null;

        byte[] buffer = getSecureRandomBytes();

        String secret = calculateSecretKey(buffer);

        EncryptionResult encryptionResult = encrpytSecret(secret, ecryptionKey);

        List<Integer> scratchCodes = calculateScratchCodes(buffer);

        if (StringUtils.isNotBlank(secret) && StringUtils.isNotBlank(encryptionResult.getEncryptionKey()) && StringUtils.isNotBlank(encryptionResult.getEncryptedText())
                && scratchCodes.size() == SCRATCH_CODES) {
            cred = new TotpCredential(userId, provider, secret, encryptionResult.getEncryptionKey(), encryptionResult.getEncryptedText(), scratchCodes);
        }

        return cred;

    }

    /**
     * fill up defined length byte[] randomly that sufficient for secreta dn scratch code
     * @return
     */
    private byte[] getSecureRandomBytes() {

        byte[] buffer = new byte[SECRET_BYTES + SCRATCH_CODES * BYTES_PER_SCRATCH_CODE];

        secureRandom.nextBytes(buffer);

        return buffer;
    }

    /**
     * use first session of random bytes to encode a secret
     * @param buffer
     * @return
     */
    private String calculateSecretKey(byte[] buffer) {

        byte[] secretKey = Arrays.copyOf(buffer, SECRET_BYTES);

        Base32 codec = new Base32();
        String encodedKey = codec.encodeToString(secretKey);

        return encodedKey;
    }

    /**
     * encrytp a secret
     * 
     * @param buffer
     * @return
     */
    private EncryptionResult encrpytSecret(String secret, String ecryptionKey) {

        EncryptionService securityService = new EncryptionService();
        EncryptionResult encryptionResult;
        if(StringUtils.isBlank(ecryptionKey)){
            encryptionResult = securityService.encrypt(secret);
        } else {
            encryptionResult = securityService.encrypt(secret, ecryptionKey);
        }

        return encryptionResult;
    }

    /**
     * split second half of bytes[] for scratch code generation
     * @param buffer
     * @return
     */
    private List<Integer> calculateScratchCodes(byte[] buffer) {
        List<Integer> scratchCodes = new ArrayList<Integer>();

        while (scratchCodes.size() < SCRATCH_CODES) {
            byte[] scratchCodeBuffer = Arrays.copyOfRange(buffer,
                    SECRET_BYTES + BYTES_PER_SCRATCH_CODE * scratchCodes.size(),
                    SECRET_BYTES + BYTES_PER_SCRATCH_CODE * scratchCodes.size() + BYTES_PER_SCRATCH_CODE);

            int scratchCode = calculateScratchCode(scratchCodeBuffer);

            if (scratchCode != SCRATCH_CODE_INVALID) {
                scratchCodes.add(scratchCode);
            } else {
                // re-gen random
                scratchCodes.add(generateScratchCode());
            }
        }

        return scratchCodes;
    }

    /**
     * generate scratch code by a given bytes[]
     * @param scratchCodeBuffer
     * @return
     */
    private int calculateScratchCode(byte[] scratchCodeBuffer) {
        if (scratchCodeBuffer.length < BYTES_PER_SCRATCH_CODE) {
            throw new IllegalArgumentException("The provided random byte buffer is too small.");
        }

        int scratchCode = 0;

        for (int i = 0; i < BYTES_PER_SCRATCH_CODE; ++i) {
            scratchCode <<= 8;
            scratchCode += scratchCodeBuffer[i];
        }

        scratchCode = (scratchCode & 0x7FFFFFFF) % SCRATCH_CODE_MODULUS;

        // Accept the scratch code only if it has exactly
        // SCRATCH_CODE_LENGTH digits.
        if (validateScratchCode(scratchCode)) {
            return scratchCode;
        } else {
            return SCRATCH_CODE_INVALID;
        }
    }

    /**
     * validate the length of scratch code
     * @param scratchCode
     * @return
     */
    boolean validateScratchCode(int scratchCode) {
        return (scratchCode >= SCRATCH_CODE_MODULUS / 10);
    }

    /**
     * used to re-generate byte[] when original byte[] does not work
     * @return
     */
    private int generateScratchCode() {
        while (true) {
            byte[] scratchCodeBuffer = new byte[BYTES_PER_SCRATCH_CODE];
            secureRandom.nextBytes(scratchCodeBuffer);

            int scratchCode = calculateScratchCode(scratchCodeBuffer);

            if (scratchCode != SCRATCH_CODE_INVALID) {
                return scratchCode;
            }
        }
    }
}
