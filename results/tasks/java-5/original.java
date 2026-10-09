
import java.security.KeyPairGenerator;
import java.security.Signature;
public class Main {
 public static void main(String[] args) throws Exception {
  var generator = KeyPairGenerator.getInstance("RSA"); generator.initialize(3072);
  var keys = generator.generateKeyPair(); var signer = Signature.getInstance("SHA256withRSA");
  byte[] msg = "controlled signature unit 5".getBytes(); signer.initSign(keys.getPrivate()); signer.update(msg);
  byte[] signature = signer.sign(); signer.initVerify(keys.getPublic()); signer.update(msg);
  if (!signer.verify(signature)) throw new IllegalStateException();
 }
}
