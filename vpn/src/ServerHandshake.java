
/**
 * Server side of the handshake.
 */

import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Base64;

import javax.security.auth.kerberos.EncryptionKey;

import java.net.ServerSocket;
import java.io.BufferedInputStream;
import java.io.ByteArrayInputStream;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;

public class ServerHandshake {
    /*
     * The parameters below should be learned by the server
     * through the handshake protocol. 
     */
    
    /* Session host/port, and the corresponding ServerSocket  */
    public static ServerSocket sessionSocket;
    public static String sessionHost;
    public static int sessionPort;    

    /* The final destination -- simulate handshake with constants */
    public static String targetHost = "localhost";
    public static int targetPort = 6789;

    protected static SessionEncrypter sessionEncrypter;
    protected static SessionDecrypter sessionDecrypter;

    private static X509Certificate serverCertificate;
    private static X509Certificate caCertificate;

    /* Security parameters key/iv should also go here. Fill in! */

    /**
     * Run server handshake protocol on a handshake socket. Here, we simulate the
     * handshake by just creating a new socket with a preassigned port number for
     * the session.
     * 
     * @throws Exception
     */
    public ServerHandshake(Socket handshakeSocket, Arguments arguments) throws Exception {
        sessionSocket = new ServerSocket(12345);
        sessionHost = sessionSocket.getInetAddress().getHostName();
        sessionPort = sessionSocket.getLocalPort();

        serverCertificate = getCertificate(arguments.get("usercert"));
        caCertificate = getCertificate(arguments.get("cacert"));

        var clientHostPort = handshakeSocket.getInetAddress().getHostAddress() + ":" + handshakeSocket.getPort();
        Logger.log("Incoming handshake connection from " + clientHostPort);

        /* ClientHello Message */
        var clientHello = new HandshakeMessage();
        clientHello.recv(handshakeSocket);

        if(!clientHello.getParameter("MessageType").equals("ClientHello")) {
            throw new Exception("Received unexpected message");
        }

        var clientCertificate = getCertificateFromByte64String(clientHello.getParameter("Certificate"));
        clientCertificate.verify(caCertificate.getPublicKey());
        clientCertificate.checkValidity();

        var serverHello = new HandshakeMessage();
        serverHello.putParameter("MessageType", "ServerHello");
        serverHello.putParameter("Certificate", Base64.getEncoder().withoutPadding().encodeToString(serverCertificate.getEncoded()));

        serverHello.send(handshakeSocket);


        var forwardMessage = new HandshakeMessage();
        forwardMessage.recv(handshakeSocket);

        if(!forwardMessage.getParameter("MessageType").equals("Forward")) {
            throw new Exception("Received unexpected message");
        }

        ServerHandshake.targetHost = forwardMessage.getParameter("TargetHost");
        ServerHandshake.targetPort = Integer.parseInt(forwardMessage.getParameter("TargetPort"));

        sessionEncrypter = new SessionEncrypter(128);
        var sessionKey = HandshakeCrypto.encrypt(sessionEncrypter.getKeyBytes(), clientCertificate.getPublicKey());

        var sessionIv = HandshakeCrypto.encrypt(sessionEncrypter.getIVBytes(), clientCertificate.getPublicKey());


        ServerHandshake.sessionSocket = new ServerSocket();
        String hostAddress = InetAddress.getLocalHost().getHostAddress();
        sessionSocket.bind(new InetSocketAddress(hostAddress, 0));
        
        var sessionMessage = new HandshakeMessage();
        sessionMessage.putParameter("MessageType", "Session");
        sessionMessage.putParameter("SessionKey", Base64.getEncoder().withoutPadding().encodeToString(sessionKey));
        sessionMessage.putParameter("SessionIV", Base64.getEncoder().withoutPadding().encodeToString(sessionIv));
        sessionMessage.putParameter("ServerHost", hostAddress);
        sessionMessage.putParameter("ServerPort", Integer.toString(sessionSocket.getLocalPort()));

        sessionMessage.send(handshakeSocket);

        sessionDecrypter = new SessionDecrypter(sessionEncrypter.getKeyBytes(), sessionEncrypter.getIVBytes());

        handshakeSocket.close();

        Logger.log("Finished server handshake");

    }

    private X509Certificate getCertificateFromByte64String(String certificateData) throws CertificateException {
        X509Certificate certificate;

        byte[] decodedCertificateData = Base64.getDecoder().decode(certificateData);
        CertificateFactory cf = CertificateFactory.getInstance("X509");
        certificate = (X509Certificate) cf.generateCertificate(new ByteArrayInputStream(decodedCertificateData));

        return certificate;
    }

    private static X509Certificate getCertificate(String filePath) throws CertificateException, FileNotFoundException {
        FileInputStream fileInputStream = new FileInputStream(filePath);
        BufferedInputStream bufferedInputStream = new BufferedInputStream(fileInputStream);
        CertificateFactory factory = CertificateFactory.getInstance("X.509");
        return (X509Certificate) factory.generateCertificate(bufferedInputStream);
    }
}
