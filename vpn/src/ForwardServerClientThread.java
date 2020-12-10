/**
 * ForwardServerClientThread handles the clients of Nakov Forward Server. It
 * connects two sockets and starts the TCP forwarding between given client
 * and its assigned server. After the forwarding is failed and the two threads
 * are stopped, closes the sockets.
 *
 */

/**
 * Modifications for IK2206:
 * - Server pool removed
 * - Two variants - client connects to listening socket or client is already connected
 *
 * Peter Sjodin, KTH
 */

import java.net.InetAddress;
import java.net.Socket;
import java.net.ServerSocket;
import java.net.SocketException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

import javax.crypto.CipherOutputStream;
import javax.crypto.NoSuchPaddingException;

import javax.crypto.CipherInputStream;

public class ForwardServerClientThread extends Thread {
    private ForwardClient mForwardClient = null;
    private Socket mClientSocket = null;
    private Socket mServerSocket = null;
    private ServerSocket mListenSocket = null;
    private boolean mBothConnectionsAreAlive = false;
    private String mClientHostPort;
    private String mServerHostPort;
    private int mServerPort;
    private String mServerHost;
    private SessionEncrypter mSessionEncrypter;
    private SessionDecrypter mSessionDecrypter;

    /**
     * Creates a client thread for handling clients of NakovForwardServer. Wait for
     * client to connect on client listening socket. A server socket is created
     * later by run() method.
     * 
     * @throws InvalidAlgorithmParameterException
     * @throws NoSuchPaddingException
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeyException
     */
    public ForwardServerClientThread(ServerSocket listensocket, String serverhost, int serverport, SessionEncrypter sessionEncrypter, SessionDecrypter sessionDecrypter) throws IOException, InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException,
            InvalidAlgorithmParameterException {
        mListenSocket = listensocket;
        mServerPort = serverport;
        mServerHost = serverhost;

        mSessionEncrypter = sessionEncrypter;
        mSessionDecrypter = sessionDecrypter;
    }

    public ServerSocket getListenSocket() {
        return mListenSocket;
    }

    /**
     * Obtains a socket for destination server. First waits for incoming connection
     * on the listen socket. Starts two threads for forwarding : "client in <-->
     * dest server out" and "dest server in <--> client out", waits until one of
     * these threads stop due to read/write failure or connection closure. Closes
     * opened connections.
     * 
     */
    public void run() {
        try {

            // Wait for incoming connection on listen socket
            mClientSocket = mListenSocket.accept();
            mClientHostPort = mClientSocket.getInetAddress().getHostName() + ":" + mClientSocket.getPort();
            Logger.log("Accepted from " + mClientHostPort + " on " + mListenSocket.getLocalPort());

            try {
                mServerSocket = new Socket(mServerHost, mServerPort);
            } catch (Exception e) {
                System.out.println("Connection failed to " + mServerHost + ":" + mServerPort);
                e.printStackTrace();
                // Prints what exception has been thrown
                System.out.println(e);
            }

            // Obtain input and output streams of server and client
            InputStream clientIn = mClientSocket.getInputStream();
            OutputStream clientOut = mClientSocket.getOutputStream();
            InputStream serverIn = mServerSocket.getInputStream();
            OutputStream serverOut = mServerSocket.getOutputStream();

            Logger.log("gefs");
            

            serverOut = mSessionEncrypter.openCipherOutputStream(serverOut);
            serverIn = mSessionDecrypter.openCipherInputStream(serverIn);

            clientOut = mSessionEncrypter.openCipherOutputStream(clientOut);
            clientIn = mSessionDecrypter.openCipherInputStream(clientIn);

            mServerHostPort = mServerHost + ":" + mServerPort;
            Logger.log("TCP Forwarding  " + mClientHostPort + " <--> " + mServerHostPort + "  started.");

            // Start forwarding of socket data between server and client
            ForwardThread clientForward = new ForwardThread(this, clientIn, serverOut);
            ForwardThread serverForward = new ForwardThread(this, serverIn, clientOut);
            mBothConnectionsAreAlive = true;
            clientForward.start();
            serverForward.start();

        } catch (IOException ioe) {
           ioe.printStackTrace();
        }
    }
 
    /**
     * connectionBroken() method is called by forwarding child threads to notify
     * this thread (their parent thread) that one of the connections (server or client)
     * is broken (a read/write failure occured). This method disconnects both server
     * and client sockets causing both threads to stop forwarding.
     */
    public synchronized void connectionBroken()
    {
        if (mBothConnectionsAreAlive) {
           // One of the connections is broken. Close the other connection and stop forwarding
           // Closing these socket connections will close their input/output streams
           // and that way will stop the threads that read from these streams
           try { mServerSocket.close(); } catch (IOException e) {}
           try { mClientSocket.close(); } catch (IOException e) {}
 
           mBothConnectionsAreAlive = false;
 
           Logger.log("TCP Forwarding  " + mClientHostPort + " <--> " + mServerHostPort + "  stopped.");
        }
    }
 
}
