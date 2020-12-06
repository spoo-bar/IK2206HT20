Skeleton files for the VPN programming project in IK2206
=======================================

This is a working port forwarder, but without encryption.

The following files are included:

  - **ForwardClient.java** ForwardClient without security protection
  - **ForwardServer.java** ForwardServer without security protection
  - **HandshakeMessage.java** A class for encoding, decoding and transmitting key-value messages 
  - **ClientHandshake.java** The client side of the handshake protocol. Currently mostly an empty class – it consists of declaration of fixed data, as a static substitute for the handshake protocol. 
  - **ServerHandshake.java** Likewise for the server side of the handshake protocol.
  - **ForwardThread.java** A class that does TCP port forwarding between two sockets
  - **ForwardServerClientThread.java** A class that sets up two-way forwarding between two socket, using the ForwardThread class
  - **Arguments.java** A class that does command line parsing (in a rather rudimentary way)
  - **Logger.java** Logging  (prints messages to the terminal)
