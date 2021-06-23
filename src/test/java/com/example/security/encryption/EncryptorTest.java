package com.example.security.encryption;

import static org.junit.jupiter.api.Assertions.assertEquals;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.junit.jupiter.api.Test;

public class EncryptorTest {
    private static final Logger logger = LogManager.getLogger(EncryptorTest.class);
    
    @Test
    public void testEncryption(){
        String expected = "JSFBYH3SI4VPYSU5ROCXJPOT";

        Encryptor encryptor = new Encryptor();

        String encText = encryptor.encrypt(expected);

        String actual = encryptor.decrypt(encText);

        logger.info("EncrytedText [{}]", encText);

        logger.info("expected [{}] vs actual [{}]", expected, actual);
        
        assertEquals(expected, actual);
    }

    @Test
    public void testEncryptionWithKey(){
        String key = "9RMj6zJ1uRehrRQBac4jHnZbSNPm+Q4dIaaajaqLdDo=";
        String expected = "JSFBYH3SI4VPYSU5ROCXJPOT";

        Encryptor encryptor = new Encryptor(key);

        String encText = encryptor.encrypt(expected);

        String actual = encryptor.decrypt(encText);

        logger.info("EncrytedText [{}]", encText);

        logger.info("expected [{}] vs actual [{}]", expected, actual);
        
        assertEquals(expected, actual);
    }
}
