package com.example;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

public class CryptoUtil {

    public byte[] encrypt(byte[] key, byte[] data) throws Exception {
        Cipher cipher = Cipher.getInstance("DES"); // 약한 암호 알고리즘 (java:S5547)
        cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "DES"));
        return cipher.doFinal(data);
    }
}
