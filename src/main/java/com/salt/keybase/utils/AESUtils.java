package com.salt.keybase.utils;

import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;


public class AESUtils {
    private static SecretKey aesKey=null;
    private static final String ENCRYPT_ALGO = "AES/GCM/NoPadding";
    private static final int TAG_LENGTH_BIT = 128;
    private static final int IV_LENGTH_BYTE = 12;
    private static final int AES_KEY_BIT = 256;

    private static final Charset UTF_8 = StandardCharsets.UTF_8;

    private static AESUtils INSTANCE;
     
    private AESUtils() throws NoSuchAlgorithmException {
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(AES_KEY_BIT, SecureRandom.getInstanceStrong());
        aesKey=keyGen.generateKey();        
    }
     
    public static AESUtils getInstance() throws NoSuchAlgorithmException {
        if(INSTANCE == null) {
            INSTANCE = new AESUtils();
        }
         
        return INSTANCE;
    }

    public byte[] getRandomNonce() {
        byte[] nonce = new byte[IV_LENGTH_BYTE];
        new SecureRandom().nextBytes(nonce);
        return nonce;
    }

    // AES-GCM needs GCMParameterSpec
    public byte[] encrypt(byte[] pText, byte[] iv) throws Exception {

        Cipher cipher = Cipher.getInstance(ENCRYPT_ALGO);
        cipher.init(Cipher.ENCRYPT_MODE, aesKey, new GCMParameterSpec(TAG_LENGTH_BIT, iv));
        byte[] encryptedText = cipher.doFinal(pText);
        return encryptedText;

    }


    public String decrypt(byte[] cText, byte[] iv) throws Exception {

        Cipher cipher = Cipher.getInstance(ENCRYPT_ALGO);
        cipher.init(Cipher.DECRYPT_MODE, aesKey, new GCMParameterSpec(TAG_LENGTH_BIT, iv));
        byte[] plainText = cipher.doFinal(cText);
        return new String(plainText, UTF_8);

    }
}
    
