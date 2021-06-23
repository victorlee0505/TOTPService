package com.example.security.encryption;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.util.Base64;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.junit.jupiter.api.Test;

public class EncryptionServiceTest {
    private static final Logger logger = LogManager.getLogger(EncryptionServiceTest.class);

    @Test
    public void testEncryption(){
        String expected = "JSFBYH3SI4VPYSU5ROCXJPOT";

        EncryptionService es = new EncryptionService();

        EncryptionResult encResult = es.encrypt(expected);

        String actual = es.decrypt(encResult.getEncryptedText(), encResult.getEncryptionKey());

        logger.info("EncrytedText [{}]", encResult.getEncryptedText());
        logger.info("EncrytedText [{}]", encResult.getEncryptionKey());

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

    @Test
    public void testEncryptionWithKey2(){
        String key = "9RMj6zJ1uRehrRQBac4jHnZbSNPm+Q4dIaaajaqLdDo=";
        String expected = "JSFBYH3SI4VPYSU5ROCXJPOT";

        Encryptor encryptor = new Encryptor(key);

        String encText = encryptor.encrypt(expected);

        Encryptor encryptor2 = new Encryptor(key);

        String actual = encryptor2.decrypt(encText);

        logger.info("EncrytedText [{}]", encText);

        logger.info("expected [{}] vs actual [{}]", expected, actual);
        
        assertEquals(expected, actual);
    }
}
