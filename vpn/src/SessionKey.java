import java.security.NoSuchAlgorithmException;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

public class SessionKey {

    private static final String ENCRYPTION_ALGORITHM = "AES";
    private SecretKey secretKey;

    public SessionKey(Integer keylength) throws NoSuchAlgorithmException {
        //create a random sessionkey of specified length in bits
        KeyGenerator keyGen = KeyGenerator.getInstance(ENCRYPTION_ALGORITHM);
        keyGen.init(keylength); // for example
        secretKey = keyGen.generateKey();
        // https://stackoverflow.com/questions/18228579/how-to-create-a-secure-random-aes-key-in-java
    }

    public SessionKey(byte[] keybytes) {
        // create from byte array
        // byte array contains an existing key that represented as a sequence of bytes
        secretKey = new SecretKeySpec(keybytes, ENCRYPTION_ALGORITHM);
        // https://stackoverflow.com/questions/14204437/convert-byte-array-to-secret-key
    }

    public SecretKey getSecretKey() {
        // symmetric key for AES
        // use class SecretKey https://docs.oracle.com/javase/8/docs/api/javax/crypto/SecretKey.html
        return secretKey;
    }

    public byte[] getKeyBytes() {
        // encrypt symmetric key
        // takes a sequence of bytes and transforms into anothe rsequence of bytes
        // convert symmetric key to a sequence of bytes
        return secretKey.getEncoded();
    }
}
