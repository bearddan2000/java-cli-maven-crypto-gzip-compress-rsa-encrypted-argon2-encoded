package example;

import de.mkammerer.argon2.Argon2;
import java.io.IOException;
import javax.xml.bind.DatatypeConverter;

public class Encode {

  private static byte[] compress(String hash) throws IOException {
    return GZIPCompression.compress(hash);
  }

  private static String decompress(byte[] hash) throws IOException {
    return GZIPCompression.decompress(hash);
  }

  private static byte[] encrypt(Encryption rsa, String hash) throws Exception {

    byte[] cipherText = rsa.do_RSAEncryption(hash);

    String newHash = DatatypeConverter.printHexBinary(cipherText);

    return compress(newHash);
  }

  private static String decrypt(Encryption rsa, byte[] hash) throws Exception {

    String decompress = decompress(hash);

    return rsa.do_RSADecryption(DatatypeConverter.parseHexBinary(decompress));
  }

  public static String hashpw(Encryption rsa, Argon2 argon2, String pass){
    char[] passwordChars = pass.toCharArray();
    String hash = argon2.hash(22, 65536, 1, passwordChars);
    argon2.wipeArray(passwordChars);

    try {

      byte[] newHash = encrypt(rsa, hash);

      return DatatypeConverter.printHexBinary(newHash);

    } catch (Exception e) {
      return null;
    }

  }

  public static boolean verify(Encryption rsa, Argon2 argon2, String pass, String hash){

    byte[] hashArray = DatatypeConverter.parseHexBinary(hash);

    try{

      hash = decrypt(rsa, hashArray);

      return argon2.verify(hash, pass.toCharArray());

    } catch (Exception e) {

      System.out.println("Encode verify error");

      e.printStackTrace();

      return false;
    }
  }
}
