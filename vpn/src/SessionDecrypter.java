import java.io.InputStream;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;

public class SessionDecrypter {

    private static final String CIPHER_ALGORITHM = "AES/CTR/NoPadding";
    private SessionKey sessionKey;
    private IvParameterSpec ivParameterSpec;
    private Cipher cipher;

    public SessionDecrypter(byte[] keybytes, byte[] ivbytes) throws InvalidKeyException, NoSuchAlgorithmException,
            NoSuchPaddingException, InvalidAlgorithmParameterException {
        // uses AES in CTR mode

        sessionKey = new SessionKey(keybytes);
        ivParameterSpec = new IvParameterSpec(ivbytes);
        initializeCipher();
    }

    public CipherInputStream openCipherInputStream(InputStream input) {
        // caller can use returned cipherinputstream to read plaintext data from it
        
        return new CipherInputStream(input, cipher);
    }

    private void initializeCipher() throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException,
            InvalidAlgorithmParameterException {
        cipher = Cipher.getInstance(CIPHER_ALGORITHM);
        cipher.init(Cipher.DECRYPT_MODE, sessionKey.getSecretKey(), ivParameterSpec);
    }

}
