package com.txstate;

import java.util.Base64;

public class Main {

  public static void main(String[] args) {

    byte[] salt = {(byte)0x43};
    byte[] dk = {(byte)0x43};

    byte[] hash = new byte[2];

    System.arraycopy(salt, 0, hash, 0, salt.length);
    System.arraycopy(dk, 0, hash, salt.length, dk.length);

    Base64.Encoder enc = Base64.getUrlEncoder().withoutPadding();
    System.out.printf("dk: %s%n", enc.encodeToString(dk));
    System.out.printf("salt: %s%n", enc.encodeToString(salt));
    System.out.printf("hash: %s%n", enc.encodeToString(hash));



    System.out.println("Using Password-Based Key Derivation Function 2 (PBKDF2)");

    String pwd = "123456";
    char[] arrayPwd = pwd.toCharArray();
    String wrongPwd = "notValid1";
    char[] wrongArrayPwd = wrongPwd.toCharArray();
    Boolean result;

    PasswordAuthentication pa = new PasswordAuthentication();

    String token = pa.hash(arrayPwd);
    System.out.println(">>> Our token is: " + token);


    result = pa.authenticate(wrongArrayPwd, token);
    System.out.println("Can we authenticate? " + result);

    result = pa.authenticate(arrayPwd, token);
    System.out.println("Can we authenticate? " + result);

  }
}
