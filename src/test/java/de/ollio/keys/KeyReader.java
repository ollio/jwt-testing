package de.ollio.keys;

import org.apache.commons.io.IOUtils;
import org.bouncycastle.jce.provider.JCERSAPrivateKey;
import org.bouncycastle.openssl.PEMReader;

import java.io.IOException;
import java.io.StringReader;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;
import java.util.logging.Level;
import java.util.logging.Logger;

public class KeyReader {
  private static final Logger log = Logger.getLogger(KeyReader.class.getName());

  static {
    try {
      // install BC, if not already done
      if (Security.getProvider("BC") == null) {
        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
        // Security.insertProviderAt(new
        // org.bouncycastle.jce.provider.BouncyCastleProvider(),2);
      }
    } catch (Throwable t) {
      log.log(Level.SEVERE, "Cannot initialize class Encryption", t);
    }
  }

  public static PrivateKey readPrivateKey() throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
    String key = IOUtils.toString(KeyReader.class.getResourceAsStream("private_key.pem"));
    PEMReader reader = new PEMReader(new StringReader(key));
    KeyPair o = (KeyPair)reader.readObject();
    return o.getPrivate();
  }

  public static PublicKey readPublicKey() throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
    String key = IOUtils.toString(KeyReader.class.getResourceAsStream("public_key.pem"));
    PEMReader reader = new PEMReader(new StringReader(key));
    return (PublicKey)reader.readObject();
  }
}
