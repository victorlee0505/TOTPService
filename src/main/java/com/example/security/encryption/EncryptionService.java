package com.example.security.encryption;

import org.apache.commons.lang3.StringUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class EncryptionService {
    private static final Logger logger = LogManager.getLogger(EncryptionService.class);
    
    public EncryptionResult encrypt(String clearText) {
		if (StringUtils.isBlank(clearText)) {
            logger.error("Input invalid");
			return null;
		}

		EncryptionResult er = new EncryptionResult();

        Encryptor encryptor = new Encryptor();
        String encryptedText = encryptor.encrypt(clearText);

		er.setEncryptedText(encryptedText);
		er.setEncryptionKey(encryptor.getKey());

		return er;
	}

    public EncryptionResult encrypt(String clearText, String key) {
		if (StringUtils.isBlank(clearText) || StringUtils.isBlank(key)) {
            logger.error("Input invalid");
			return null;
		}

		EncryptionResult er = new EncryptionResult();

        Encryptor encryptor = new Encryptor(key);
        String encryptedText = encryptor.encrypt(clearText);

		er.setEncryptedText(encryptedText);
		er.setEncryptionKey(encryptor.getKey());

		return er;
	}

    public String decrypt(String encryptedText, String key) {
		if (StringUtils.isBlank(key) || StringUtils.isBlank(encryptedText)) {
			return null;
		}
		Encryptor encryptor = new Encryptor(key);
		return encryptor.decrypt(encryptedText);
	}


}
