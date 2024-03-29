// some stuff from ForwardClient.java

/**
 * Client side of the handshake.
 */

import java.net.Socket;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.SignatureException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateFactory;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;
import java.io.BufferedInputStream;
import java.io.ByteArrayInputStream;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;

public class ClientHandshake {
    /*
     * The parameters below should be learned by the client through the handshake
     * protocol.
     */

    /* Session host/port */
    public String sessionHost = "localhost";
    public int sessionPort = 12345;


    protected static SessionEncrypter sessionEncrypter;
    protected static SessionDecrypter sessionDecrypter;

    private Socket handshakeSocket;

    /* Security parameters key/iv should also go here. Fill in! */

    private X509Certificate clientCertificate;
    private X509Certificate caCertificate;
    private PrivateKey clientPrivateKey;

    /**
     * Run client handshake protocol on a handshake socket. Here, we do nothing, for
     * now.
     * 
     * @throws Exception
     */
    public ClientHandshake(Socket handshakeSocket) throws Exception {
        this.handshakeSocket = handshakeSocket;
    }

    protected void doHandshake(Arguments arguments) throws CertificateEncodingException, IOException, Exception,
            CertificateException, NoSuchAlgorithmException, InvalidKeyException, NoSuchProviderException,
            SignatureException, CertificateExpiredException, CertificateNotYetValidException {


        this.clientCertificate = getCertificate(arguments.get("usercert"));
        this.caCertificate = getCertificate(arguments.get("cacert"));
        this.clientPrivateKey = getPrivateKeyFromFile(arguments.get("key"));


        HandshakeMessage clientHello = new HandshakeMessage();
        clientHello.putParameter("MessageType", "ClientHello");
        clientHello.putParameter("Certificate",
                Base64.getEncoder().withoutPadding().encodeToString(clientCertificate.getEncoded()));
        clientHello.send(handshakeSocket);

        HandshakeMessage serverHello = new HandshakeMessage();
        serverHello.recv(handshakeSocket);

        if (!serverHello.getParameter("MessageType").equals("ServerHello")) {
            throw new Exception("Did not understand message");
            // TODO - better message? check if they ask for something
        }

        X509Certificate serveCertificate = getCertificateFromByte64String(serverHello.getParameter("Certificate"));
        serveCertificate.verify(caCertificate.getPublicKey());
        serveCertificate.checkValidity();

        HandshakeMessage forwardMessage = new HandshakeMessage();
        forwardMessage.putParameter("MessageType", "Forward"); // TODO - see if this is what the protocol is
        forwardMessage.putParameter("TargetHost", arguments.get("targethost"));
        forwardMessage.putParameter("TargetPort", arguments.get("targetport"));
        forwardMessage.send(handshakeSocket);

        HandshakeMessage sessionMessage = new HandshakeMessage();
        sessionMessage.recv(handshakeSocket);

        if (!sessionMessage.getParameter("MessageType").equals("Session")) {
            throw new Exception("Received unexpected message"); // TODO
        }

        sessionHost = sessionMessage.getParameter("ServerHost");
        sessionPort = Integer.parseInt(sessionMessage.getParameter("ServerPort"));

        var sessionKey = HandshakeCrypto.decrypt(Base64.getDecoder().decode(sessionMessage.getParameter("SessionKey")),
                clientPrivateKey);

                Logger.log(sessionMessage.getParameter("SessionIV"));
        var sessionIv = HandshakeCrypto.decrypt(Base64.getDecoder().decode(sessionMessage.getParameter("SessionIV")),
                clientPrivateKey);

        sessionEncrypter = new SessionEncrypter(sessionKey, sessionIv);
        sessionDecrypter = new SessionDecrypter(sessionKey, sessionIv);

        handshakeSocket.close();

        Logger.log("Finished with handshake");
    }

    public X509Certificate getCertificateFromByte64String(String certificateData) throws CertificateException {
        X509Certificate certificate;

        byte[] decodedCertificateData = Base64.getDecoder().decode(certificateData);
        CertificateFactory cf = CertificateFactory.getInstance("X509");
        certificate = (X509Certificate) cf.generateCertificate(new ByteArrayInputStream(decodedCertificateData));

        return certificate;
    }

    public PrivateKey getPrivateKeyFromFile(String keyFilePath)
            throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
        Path path = Paths.get(keyFilePath);
        byte[] privKeyByteArray = Files.readAllBytes(path);

        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(privKeyByteArray);

        KeyFactory keyFactory = KeyFactory.getInstance("RSA");

        PrivateKey privateKey = keyFactory.generatePrivate(keySpec);

        return privateKey;
    }

    private static X509Certificate getCertificate(String filePath) throws CertificateException, FileNotFoundException {
        FileInputStream fileInputStream = new FileInputStream(filePath);
        BufferedInputStream bufferedInputStream = new BufferedInputStream(fileInputStream);
        CertificateFactory factory = CertificateFactory.getInstance("X.509");
        return (X509Certificate) factory.generateCertificate(bufferedInputStream);
    }
}
