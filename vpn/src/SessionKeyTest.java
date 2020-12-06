import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertArrayEquals;
import org.junit.Test;
import javax.crypto.SecretKey;
import java.security.NoSuchAlgorithmException;

public class SessionKeyTest {
    private byte[] keybytes = {(byte) 0x88, (byte) 0x91, (byte) 0x67, (byte) 0xc7,
            (byte) 0x44, (byte) 0xa4, (byte) 0xc8, (byte) 0x2d,
            (byte) 0x81, (byte) 0x41, (byte) 0xb4, (byte) 0xce,
            (byte) 0x4f, (byte) 0x38, (byte) 0xc7, (byte) 0xd1};

    @Test
    public void testSecretKeyIsAES() throws NoSuchAlgorithmException {
        SessionKey key = new SessionKey(128);
        SecretKey secret = key.getSecretKey();
        
        assertEquals(secret.getAlgorithm(), "AES");
    }

    @Test
    public void testSameStringGivesSameKey() throws NoSuchAlgorithmException {
        SessionKey key1 = new SessionKey(keybytes);
        SessionKey key2 = new SessionKey(keybytes);

        assertEquals(key1.getSecretKey(), key2.getSecretKey());
    }

    @Test
    public void testEncodeKeyEqualsString() throws NoSuchAlgorithmException {
        SessionKey key = new SessionKey(keybytes);

        assertArrayEquals(keybytes, key.getKeyBytes());
    }

    @Test
    public void testGeneratedKeysEqual() throws NoSuchAlgorithmException {
        SessionKey key1 = new SessionKey(128);
        SessionKey key2 = new SessionKey(key1.getKeyBytes());

        assertEquals(key1.getSecretKey(), key2.getSecretKey());
    }
}
