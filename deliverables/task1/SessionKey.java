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
        keyGen.init(keylength);
        secretKey = keyGen.generateKey();
    }

    public SessionKey(byte[] keybytes) {
        // create from byte array, contains an existing key that represented as a sequence of bytes
        secretKey = new SecretKeySpec(keybytes, ENCRYPTION_ALGORITHM);
    }

    public SecretKey getSecretKey() {
        return secretKey;
    }

    public byte[] getKeyBytes() {
        // convert key to a sequence of bytes
        return secretKey.getEncoded();
    }
}
