import java.io.OutputStream;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

import javax.crypto.Cipher;
import javax.crypto.CipherOutputStream;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;

public class SessionEncrypter {

    private static final String CIPHER_ALGORITHM = "AES/CTR/NoPadding";
    private SessionKey sessionKey;
    private IvParameterSpec ivParameterSpec;
    private Cipher cipher;

    public SessionEncrypter(Integer keylength) throws NoSuchAlgorithmException, InvalidKeyException,
            NoSuchPaddingException, InvalidAlgorithmParameterException {

        sessionKey = new SessionKey(keylength);
        ivParameterSpec = new IvParameterSpec(this.getRandomNonce());
        initializeCipher();

    }

    public SessionEncrypter(byte[] keybytes, byte[] ivbytes) throws InvalidKeyException, NoSuchAlgorithmException,
            NoSuchPaddingException, InvalidAlgorithmParameterException {

        sessionKey = new SessionKey(keybytes);
        ivParameterSpec = new IvParameterSpec(ivbytes);
        initializeCipher();

    }

    public byte[] getKeyBytes() {
        return sessionKey.getKeyBytes();
    }

    public byte[] getIVBytes() {
        return ivParameterSpec.getIV();
    }

    public CipherOutputStream openCipherOutputStream(OutputStream output) {
        return new CipherOutputStream(output, cipher);
    }

    private byte[] getRandomNonce() {
        byte[] nonce = new byte[16];
        new SecureRandom().nextBytes(nonce);
        return nonce;
    }

    private void initializeCipher() throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException,
            InvalidAlgorithmParameterException {

        cipher = Cipher.getInstance(CIPHER_ALGORITHM);
        cipher.init(Cipher.ENCRYPT_MODE, sessionKey.getSecretKey(), ivParameterSpec);
        
    }
}
