import java.io.FileInputStream;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;

import java.math.BigInteger;

import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

import java.security.interfaces.DSAParams;
import java.security.interfaces.DSAPrivateKey;

public class DSYay {

  static final byte[] SHORT_ID = new byte[] { (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF }; // 0xFFFFFFFF

  static final KeyPairGenerator DSA;

  static {
    try {
      DSA = KeyPairGenerator.getInstance("DSA");
    } catch (NoSuchAlgorithmException e) {
      throw new RuntimeException(e);
    }
  }

  static final SecureRandom SHA1PRNG;

  static {
    try {
      SHA1PRNG = SecureRandom.getInstance("SHA1PRNG");
    } catch (NoSuchAlgorithmException e) {
      throw new RuntimeException(e);
    }
  }

  static final MessageDigest SHA1;

  static {
    try {
      SHA1 = MessageDigest.getInstance("SHA1");
    } catch (NoSuchAlgorithmException e) {
      throw new RuntimeException(e);
    }
  }

  public static void main(String args[]) {
    System.out.println("Here we go!");

    DSA.initialize(1024, SHA1PRNG);

    final DSAPrivateKey key = (DSAPrivateKey) DSA.generateKeyPair().getPrivate();
    final DSAParams parameters = key.getParams();

    final BigInteger p = parameters.getP();
    final byte[] p_mpi = BigIntegers.asMPI(p);

    final BigInteger q = parameters.getQ();
    final byte[] q_mpi = BigIntegers.asMPI(q);

    final BigInteger g = parameters.getG();
    final byte[] g_mpi = BigIntegers.asMPI(g);

    BigInteger e /* y */;
    BigInteger x = key.getX();

    byte digest[];

    while (true) {
      x = x.subtract(BigInteger.ONE);
      e = g.modPow(x, p);

      SHA1.reset();

      SHA1.update(p_mpi);
      SHA1.update(q_mpi);
      SHA1.update(g_mpi);
      SHA1.update(BigIntegers.asMPI(e));

      digest = SHA1.digest();

      if ((digest[17] == SHORT_ID[1]) && (digest[18] == SHORT_ID[2]) && (digest[19] == SHORT_ID[3])) {
        System.out.printf("%n");
        System.out.println(DSYay.bytesToHex(digest));
        System.out.println("p:" + DSYay.bytesToHex(p.toByteArray()));
        System.out.println("q:" + DSYay.bytesToHex(q.toByteArray()));
        System.out.println("g:" + DSYay.bytesToHex(g.toByteArray()));
        System.out.println("e:" + DSYay.bytesToHex(e.toByteArray()));
        System.out.println("x:" + DSYay.bytesToHex(x.toByteArray()));
        
        if (digest[16] == SHORT_ID[0]) {
          break;
        }
      }
    }
  }

  final protected static char[] hexArray = "0123456789ABCDEF".toCharArray();
  public static String bytesToHex(byte[] bytes) {
      char[] hexChars = new char[bytes.length * 2];
      for ( int j = 0; j < bytes.length; j++ ) {
          int v = bytes[j] & 0xFF;
          hexChars[j * 2] = hexArray[v >>> 4];
          hexChars[j * 2 + 1] = hexArray[v & 0x0F];
      }
      return new String(hexChars);
  }

  static final class BigIntegers {
    // Returns a byte array without a leading zero byte if present in the signed encoding.
    public static byte[] asUnsignedByteArray(BigInteger value) {
      byte[] bytes = value.toByteArray();
      if (bytes[0] == 0) {
        byte[] tmp = new byte[bytes.length - 1];
        System.arraycopy(bytes, 1, tmp, 0, tmp.length);
        return tmp;
      }
      return bytes;
    }

    public static byte[] asMPI(BigInteger value) {
      byte[] tmp = BigIntegers.asUnsignedByteArray(value);
      byte[] tmp2 = Integers.asUnsignedByteArray(tmp.length);

      byte[] bytes = new byte[tmp2.length + tmp.length];
      System.arraycopy(tmp2, 0, bytes, 0, tmp2.length);
      System.arraycopy(tmp, 0, bytes, tmp2.length, tmp.length);

      return bytes;
    }
  }

  static final class Integers {
    public static byte[] asUnsignedByteArray(int value) {
      byte[] bytes = new byte[4];
    	for (int i = 0; i < 4; i++) {
    		int offset = (bytes.length - 1 - i) * 8;
    		bytes[i] = (byte) ((value >>> offset) & 0xFF);
    	}
      return bytes;
    }
  }

}
