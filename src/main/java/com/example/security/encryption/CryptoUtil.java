package com.example.security.encryption;

import java.util.Base64;

public class CryptoUtil {

    protected static byte[] getBytes(String s)  {
		return Base64.getDecoder().decode(s);
	}

	protected static String getString(byte[] bytes)  {
		return Base64.getEncoder().encodeToString(bytes);
	}

	protected static String encodeBase64(byte[] b)  {
		return Base64.getEncoder().encodeToString(b);
	}

	protected static byte[] decodeBase64(String s)  {
		return Base64.getDecoder().decode(s);
	}
    
}
