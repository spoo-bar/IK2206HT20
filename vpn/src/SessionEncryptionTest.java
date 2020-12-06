import java.util.*;
import javax.crypto.*;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertArrayEquals;

import org.junit.Test;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;

public class SessionEncryptionTest  {
    static String PLAINSTRING = "Time flies like an arrow. Fruit flies like a banana.";
    static Integer KEYLENGTH = 128;
    // Encoded key and IV (Base64-encoding with padding) for decryption with given key/iv and ciphertext
    static String ENCODEDKEY = "r2X8tjnKkFlzugajYIDBCw==";
    static byte[] KEYBYTES = {(byte) 0xaf, (byte) 0x65, (byte) 0xfc, (byte) 0xb6, (byte) 0x39, (byte) 0xca, (byte) 0x90, (byte) 0x59, (byte) 0x73, (byte) 0xba, (byte) 0x06, (byte) 0xa3, (byte) 0x60, (byte) 0x80, (byte) 0xc1, (byte) 0x0b};
    static byte[] IVBYTES = {(byte) 0x3b, (byte) 0xbd, (byte) 0xfb, (byte) 0x20, (byte) 0x28, (byte) 0xb9, (byte) 0xe9, (byte) 0x53, (byte) 0x29, (byte) 0xa7, (byte) 0x65, (byte) 0x00, (byte) 0x9b, (byte) 0x90, (byte) 0x70, (byte) 0x2b};

    static String ENCODEDIV = "O737ICi56VMpp2UAm5BwKw==";
    // Ciphertext obtained by encrypting plaintext with AES/CTR/NoPadding cipher and ENCODEDKEY/ENCODEDIV
    static byte[] CIPHERDATA = {(byte) 0x4e, (byte) 0x19, (byte) 0xec, (byte) 0xd1, (byte) 0x29, (byte) 0xb4, (byte) 0x2f,
                                (byte) 0x1e, (byte) 0x67, (byte) 0x1c, (byte) 0x6f, (byte) 0x57, (byte) 0xdb, (byte) 0xe9,
                                (byte) 0xc6, (byte) 0xde, (byte) 0x32, (byte) 0x9c, (byte) 0xdf, (byte) 0xf3, (byte) 0x1c,
                                (byte) 0x73, (byte) 0xef, (byte) 0xf4, (byte) 0xd7, (byte) 0xf3, (byte) 0x26, (byte) 0x9e,
                                (byte) 0x0d, (byte) 0xdd, (byte) 0x94, (byte) 0x0d, (byte) 0xa7, (byte) 0x4b, (byte) 0xe4,
                                (byte) 0xa8, (byte) 0x06, (byte) 0xe4, (byte) 0x01, (byte) 0x49, (byte) 0x14, (byte) 0xc5,
                                (byte) 0x33, (byte) 0xe2, (byte) 0x59, (byte) 0x79, (byte) 0x5c, (byte) 0x6c, (byte) 0x28,
                                (byte) 0x59, (byte) 0xb3, (byte) 0xf2};


    /* Encrypt a byte array plaintext with sessionencrypter and return a byte array ciphertext */

    private byte[] encryptByteArray(byte[] plaintext, SessionEncrypter sessionencrypter) throws Exception {
        try (
             ByteArrayOutputStream cipherByteArrayOutputStream = new ByteArrayOutputStream();
             CipherOutputStream cipherout = sessionencrypter.openCipherOutputStream(cipherByteArrayOutputStream);
             ) {
            cipherout.write(plaintext);
            return cipherByteArrayOutputStream.toByteArray();
        }
    }

    /* Decrypt a byte array ciphertext with sessiondecrypter and return a byte array plaintext */
    
    private byte[] decryptByteArray(byte[] ciphertext, SessionDecrypter sessiondecrypter) throws Exception {

        // Attach input file to decrypter, and open output file
        try (
             ByteArrayInputStream cipherByteArrayInputStream = new ByteArrayInputStream(ciphertext);
             CipherInputStream cipherin = sessiondecrypter.openCipherInputStream(cipherByteArrayInputStream);
             ) {
            byte[] plainout = cipherin.readAllBytes();
            return plainout;
        }
    }

    /* Test that SessionEncryptors are not generated with the same key */
    @Test
    public void testSecretKeysAreUnique() throws Exception {
        SessionEncrypter sessionencrypter1 = new SessionEncrypter(KEYLENGTH);
        SessionEncrypter sessionencrypter2 = new SessionEncrypter(KEYLENGTH);

        assertFalse(Arrays.equals(sessionencrypter1.getKeyBytes(), sessionencrypter2.getKeyBytes()));
    }

    /* Test that SessionEncryptors are not generated with the same IV */
    @Test
    public void testIVsAreUnique() throws Exception {
        SessionEncrypter sessionencrypter1 = new SessionEncrypter(KEYLENGTH);
        SessionEncrypter sessionencrypter2 = new SessionEncrypter(KEYLENGTH);

        assertFalse(Arrays.equals(sessionencrypter1.getIVBytes(), sessionencrypter2.getIVBytes()));
    }

    /* Test that encryption followed by decryption gives original plaintext */
    @Test
    public void testEncryptThenDecryptGivesPlaintext() throws Exception {
     // Create encrypter instance for a given key length
        SessionEncrypter sessionencrypter = new SessionEncrypter(KEYLENGTH);
        SessionDecrypter sessiondecrypter = new SessionDecrypter(sessionencrypter.getKeyBytes(),
                                                                 sessionencrypter.getIVBytes());
        byte[] plaintext = PLAINSTRING.getBytes();
        byte[] ciphertext = encryptByteArray(plaintext, sessionencrypter);
        byte[] decipheredtext = decryptByteArray(ciphertext, sessiondecrypter);

        assertArrayEquals(decipheredtext, plaintext);
    }

    /* Test that decryption with given ciphertext, key and IV returns plaintext.
       Key and IV are given as byte arrays.
       Ciphertext was created with AES/CTR/NoPadding cipher.
    */
    @Test
    public void testDecryptedCiphertextGivesPlaintext() throws Exception {

        byte[] plaintext = PLAINSTRING.getBytes();
        SessionDecrypter sessiondecrypter = new SessionDecrypter(KEYBYTES, IVBYTES);
        byte[] decipheredtext = decryptByteArray(CIPHERDATA, sessiondecrypter);

        assertArrayEquals(decipheredtext, plaintext);
    }
}
