import java.io.BufferedInputStream;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

public class HandshakeCrypto {

    private static final String CERTIFICATE_TYPE = "X.509";
    private static final String CIPHER_ALGORITHM = "RSA";

    public static byte[] encrypt(byte[] plaintext, Key key) throws NoSuchAlgorithmException, NoSuchPaddingException,
            InvalidKeyException, IllegalBlockSizeException, BadPaddingException {

        Cipher cipher = Cipher.getInstance(CIPHER_ALGORITHM);
        cipher.init(Cipher.ENCRYPT_MODE, key);

        return cipher.doFinal(plaintext);
    }

    public static byte[] decrypt(byte[] ciphertext, Key key) throws NoSuchAlgorithmException, NoSuchPaddingException,
            InvalidKeyException, IllegalBlockSizeException, BadPaddingException {

        Cipher cipher = Cipher.getInstance(CIPHER_ALGORITHM);
        cipher.init(Cipher.DECRYPT_MODE, key);

        return cipher.doFinal(ciphertext);
    }

    public static PublicKey getPublicKeyFromCertFile(String certfile)
            throws CertificateException, FileNotFoundException {

        return getCertificate(certfile).getPublicKey();
    }

    public static PrivateKey getPrivateKeyFromKeyFile(String keyfile)
            throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {

        var privateKey = Files.readAllBytes(Paths.get(keyfile));
        var encodedKeySpec = new PKCS8EncodedKeySpec(privateKey);
        var keyFactory = KeyFactory.getInstance(CIPHER_ALGORITHM);
        return keyFactory.generatePrivate(encodedKeySpec);
    }

    private static X509Certificate getCertificate(String filePath) throws CertificateException, FileNotFoundException {

        var fileInputStream = new FileInputStream(filePath);
        var bufferedInputStream = new BufferedInputStream(fileInputStream);
        var factory = CertificateFactory.getInstance(CERTIFICATE_TYPE);
        return (X509Certificate) factory.generateCertificate(bufferedInputStream);
    }
}
