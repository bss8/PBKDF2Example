package com.txstate;

import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.util.Arrays;
import java.util.Base64;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

/**
 * Hash passwords for storage, and test passwords against password tokens.
 * Instances of this class can be used concurrently by multiple threads.
 */
public final class PasswordAuthentication {

  /**
   * Each token produced by this class uses this identifier as a prefix.
   */
  public static final String ID = "$TXST$";

  /**
   * The minimum recommended cost, used by default
   */
  public static final int DEFAULT_COST = 16;
  private static final String ALGORITHM = "PBKDF2WithHmacSHA512";
  private static final int SIZE = 128;
  private static final Pattern layout = Pattern
      .compile("\\$TXST\\$(\\d\\d?)\\$(.{43})");
  private final SecureRandom random;
  private final int cost;

  public PasswordAuthentication() {
    this(DEFAULT_COST);
  }

  /**
   * Create a password manager with a specified cost
   * @param cost the exponential computational cost of hashing a password, 0 to 30
   */
  public PasswordAuthentication(int cost) {
    System.out.println("Create a password manager with a specified cost (default 16): " + cost);
    iterations(cost); /* Validate cost */
    this.cost = cost;
    this.random = new SecureRandom();
  }

  private static int iterations(int cost) {
    if ((cost < 0) || (cost > 30))
      throw new IllegalArgumentException("cost: " + cost);
    int a = 1 << cost;
    System.out.println("Bitshift left (same as multiplying by 2 each time): 1 << cost: " + a);
    return a;
  }

  /**
   * Hash a password for storage.
   * @return a secure authentication token to be stored for later authentication
   */
  public String hash(char[] password) {
    System.out.println("generate random bytes and places them into a user-supplied byte array.");
    byte[] salt = new byte[SIZE / 8];

    random.nextBytes(salt);

    byte[] dk = pbkdf2(password, salt, 1 << cost);
    System.out.println("Byte array of pbkdf2 algorithm: " + Arrays
        .toString(dk));

    byte[] hash = new byte[salt.length + dk.length];
    System.out.println("hash byte on instantiation (empty): " + Arrays.toString(hash));

    System.arraycopy(salt, 0, hash, 0, salt.length);
    System.arraycopy(dk, 0, hash, salt.length, dk.length);

    Base64.Encoder enc = Base64.getUrlEncoder().withoutPadding();
    System.out.println(enc);

    System.out.printf("salt: %s%n", enc.encodeToString(salt));
    System.out.printf("hash: %s%n", enc.encodeToString(hash));

    return ID + cost + '$' + enc.encodeToString(hash);
  }

  /**
   * Authenticate with a password and a stored password token.
   * @return true if the password and token match
   */
  public boolean authenticate(char[] password, String token) {
    Matcher m = layout.matcher(token);

    if (!m.matches())
      throw new IllegalArgumentException("Invalid token format");

    int iterations = iterations(Integer.parseInt(m.group(1)));
    System.out.println("Decoded Iterations: " + iterations);

    byte[] hash = Base64.getUrlDecoder().decode(m.group(2));
    System.out.println("Decoded hash:" + Arrays.toString(hash));

    byte[] salt = Arrays.copyOfRange(hash, 0, SIZE / 8);
    System.out.println("Decoded salt:" + Arrays.toString(salt));

    byte[] check = pbkdf2(password, salt, iterations);
    System.out.println("Check:" + Arrays.toString(check));

    int zero = 0;

    System.out.println("Bitwise OR zero with hash bitwise XOR with check[idx]");
    for (int idx = 0; idx < check.length; ++idx) {

      //zero |= hash[salt.length + idx] ^ check[idx];
      System.out.println(hash[salt.length + idx] + " || " + check[idx]);
      zero = zero | hash[salt.length + idx] ^ check[idx];
      System.out.println(zero);
    }

    return zero == 0;
  }

  private static byte[] pbkdf2(char[] password, byte[] salt, int iterations) {
    KeySpec spec = new PBEKeySpec(password, salt, iterations, SIZE);

    try {

      SecretKeyFactory f = SecretKeyFactory.getInstance(ALGORITHM);
      return f.generateSecret(spec).getEncoded();

    } catch (NoSuchAlgorithmException ex) {
      throw new IllegalStateException("Missing algorithm: " + ALGORITHM, ex);
    } catch (InvalidKeySpecException ex) {
      throw new IllegalStateException("Invalid SecretKeyFactory", ex);
    }
  }

}