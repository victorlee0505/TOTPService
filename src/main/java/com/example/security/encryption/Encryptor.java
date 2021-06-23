package com.example.security.encryption;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.xml.bind.DatatypeConverter;

import com.example.security.constants.TotpConstant;

import org.apache.commons.lang3.ArrayUtils;

/**
 * from https://www.baeldung.com/java-aes-encryption-decryption
 */
public class Encryptor {

    private Cipher cipher;
    private Key key;
    private IvParameterSpec iv;

    public Encryptor(Cipher cipher, Key key, IvParameterSpec iv) {
        this.cipher = cipher;
        this.key = key;
        this.iv = iv;
    }

    public Encryptor(String key) {
        try {
            this.cipher = Cipher.getInstance(TotpConstant.CIPHER_SPEC);
            this.key = new SecretKeySpec(CryptoUtil.decodeBase64(key), TotpConstant.CIPHER_ALGO);
            this.iv = generateIV();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
            throw new RuntimeException(e);
        } catch (NoSuchPaddingException e) {
            e.printStackTrace();
            throw new RuntimeException(e);
        }
    }

    public Encryptor() {
        try {
            this.cipher = Cipher.getInstance(TotpConstant.CIPHER_SPEC);
            this.key = generateKey(TotpConstant.KEY_SIZE);
            this.iv = generateIV();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
            throw new RuntimeException(e);
        } catch (NoSuchPaddingException e) {
            e.printStackTrace();
            throw new RuntimeException(e);
        }
    }

    public String encrypt(String clearText) {
        try {
            this.cipher.init(Cipher.ENCRYPT_MODE, this.key, this.iv);
            byte[] cipherText = cipher.doFinal(CryptoUtil.getBytes(clearText));
            byte[] ivBytes = iv.getIV();

            byte[] message = ArrayUtils.addAll(ivBytes, cipherText);

            return CryptoUtil.encodeBase64(message);
        } catch (InvalidKeyException e) {
            e.printStackTrace();
            throw new RuntimeException(e);
        } catch (InvalidAlgorithmParameterException e) {
            e.printStackTrace();
            throw new RuntimeException(e);
        } catch (IllegalBlockSizeException e) {
            e.printStackTrace();
            throw new RuntimeException(e);
        } catch (BadPaddingException e) {
            e.printStackTrace();
            throw new RuntimeException(e);
        }
    }

    public String decrypt(String encryptedText) {
        try {
            byte[] message = CryptoUtil.decodeBase64(encryptedText);
            IvParameterSpec iv = getIVfromMessage(message);
            byte[] cipherByte = ArrayUtils.subarray(message, iv.getIV().length, message.length);

            this.cipher.init(Cipher.DECRYPT_MODE, this.key, iv);
            byte[] plainText = cipher.doFinal(cipherByte);
            return CryptoUtil.getString(plainText);
        } catch (InvalidKeyException e) {
            e.printStackTrace();
            throw new RuntimeException(e);
        } catch (InvalidAlgorithmParameterException e) {
            e.printStackTrace();
            throw new RuntimeException(e);
        } catch (IllegalBlockSizeException e) {
            e.printStackTrace();
            throw new RuntimeException(e);
        } catch (BadPaddingException e) {
            e.printStackTrace();
            throw new RuntimeException(e);
        }
    }

    public static SecretKey generateKey(int n) throws NoSuchAlgorithmException {
        KeyGenerator keyGenerator = KeyGenerator.getInstance(TotpConstant.CIPHER_ALGO);
        keyGenerator.init(n);
        SecretKey key = keyGenerator.generateKey();
        return key;
    }

    public String getKey() {
        return DatatypeConverter.printBase64Binary(key.getEncoded());
    }

    public IvParameterSpec generateIV() {
        byte[] iv = new byte[cipher.getBlockSize()];
        new SecureRandom().nextBytes(iv);
        return new IvParameterSpec(iv);
    }

    private IvParameterSpec getIVfromMessage(byte[] message) {
		int ivSize = generateIV().getIV().length;
		if (message.length <= ivSize) {
			throw new RuntimeException("Message is too short - can't contain Initial Vector");
		}
        byte[] iv = ArrayUtils.subarray(message, 0, ivSize);

		return new IvParameterSpec(iv);
	}

}
