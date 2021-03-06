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
        logger.info("EncrytionKey [{}]", encryptor.getKey());

        logger.info("expected [{}] vs actual [{}]", expected, actual);
        
        assertEquals(expected, actual);
    }

    @Test
    public void testEncryption2(){
        String expected = "JSFBYH3SI4VPYSU5ROCXJPOT";

        Encryptor encryptor = new Encryptor();

        String encText = encryptor.encrypt(expected);

        logger.info("encryptor1 ========");
        logger.info("EncrytedText [{}]", encText);
        logger.info("EncrytionKey [{}]", encryptor.getKey());

        Encryptor encryptor2 = new Encryptor(encryptor.getKey());

        String actual = encryptor2.decrypt(encText);

        logger.info("encryptor2 ========");
        logger.info("EncrytionKey [{}]", encryptor2.getKey());

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
