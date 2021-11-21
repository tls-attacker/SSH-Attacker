/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2021 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.state;

import de.rub.nds.sshattacker.core.config.Config;
import de.rub.nds.sshattacker.core.connection.AliasedConnection;
import de.rub.nds.sshattacker.core.constants.*;
import de.rub.nds.sshattacker.core.constants.PacketLayerType;
import de.rub.nds.sshattacker.core.crypto.hash.ExchangeHash;
import de.rub.nds.sshattacker.core.crypto.kex.KeyExchange;
import de.rub.nds.sshattacker.core.exceptions.ConfigurationException;
import de.rub.nds.sshattacker.core.exceptions.TransportHandlerConnectException;
import de.rub.nds.sshattacker.core.protocol.common.layer.MessageLayer;
import de.rub.nds.sshattacker.core.protocol.packet.layer.AbstractPacketLayer;
import de.rub.nds.sshattacker.core.protocol.packet.layer.PacketLayerFactory;
import de.rub.nds.sshattacker.core.workflow.chooser.Chooser;
import de.rub.nds.sshattacker.core.workflow.chooser.ChooserFactory;
import de.rub.nds.tlsattacker.transport.ConnectionEndType;
import de.rub.nds.tlsattacker.transport.TransportHandler;
import de.rub.nds.tlsattacker.transport.TransportHandlerFactory;
import java.io.IOException;
import java.util.List;
import java.util.Optional;

public class SshContext {

    /** Static configuration for SSH-Attacker */
    private Config config;

    private Chooser chooser;

    /** Connection used to communicate with the remote peer */
    private AliasedConnection connection;

    private TransportHandler transportHandler;
    /** If set to true, an exception was received from the transport handler */
    private boolean receivedTransportHandlerException = false;

    /** The currently active packet layer type */
    private PacketLayerType packetLayerType;
    /** A layer to serialize packets */
    private AbstractPacketLayer packetLayer;
    /** A layer to serialize messages */
    private MessageLayer messageLayer = new MessageLayer(this);

    /**
     * Sequence number used to generate MAC when sending packages. The sequence number is unsigned,
     * initialized to 0 and wraps around at 2^32.
     */
    private Integer writeSequenceNumber;
    /**
     * Sequence number used to verify the MAC of received packages. The sequence number is unsigned,
     * initialized to 0 and wraps around at 2^32.
     */
    private Integer readSequenceNumber;

    // region Version Exchange
    /** Client protocol and software version string starting with the SSH version (SSH-2.0-...) */
    private String clientVersion;
    /** Client comment sent alongside protocol and software version */
    private String clientComment;
    /** Server protocol and software version string starting with the SSH version (SSH-2.0-...) */
    private String serverVersion;
    /** Server comment sent alongside protocol and software version */
    private String serverComment;
    /** Defines the end of the VersionExchangeMessage */
    private String endofMessageSequence;

    // endregion

    // region Key Exchange Initialization
    /** Client cookie containing 16 random bytes */
    private byte[] clientCookie;
    /** Server cookie containing 16 random bytes */
    private byte[] serverCookie;
    /** List of key exchange algorithms supported by the remote peer */
    private List<KeyExchangeAlgorithm> clientSupportedKeyExchangeAlgorithms;
    /** List of key exchange algorithms supported by the server */
    private List<KeyExchangeAlgorithm> serverSupportedKeyExchangeAlgorithms;
    /** List of host key algorithms supported by the client */
    private List<PublicKeyAuthenticationAlgorithm> clientSupportedHostKeyAlgorithms;
    /** List of host key algorithms supported by the server */
    private List<PublicKeyAuthenticationAlgorithm> serverSupportedHostKeyAlgorithms;
    /** List of encryption algorithms (client to server) supported by the client */
    private List<EncryptionAlgorithm> clientSupportedCipherAlgorithmsClientToServer;
    /** List of encryption algorithms (server to client) supported by the client */
    private List<EncryptionAlgorithm> clientSupportedCipherAlgorithmsServerToClient;
    /** List of encryption algorithms (client to server) supported by the server */
    private List<EncryptionAlgorithm> serverSupportedCipherAlgorithmsClientToServer;
    /** List of encryption algorithms (server to client) supported by the server */
    private List<EncryptionAlgorithm> serverSupportedCipherAlgorithmsServerToClient;
    /** List of MAC algorithms (client to server) supported by the client */
    private List<MacAlgorithm> clientSupportedMacAlgorithmsClientToServer;
    /** List of MAC algorithms (server to client) supported by the client */
    private List<MacAlgorithm> clientSupportedMacAlgorithmsServerToClient;
    /** List of MAC algorithms (client to server) supported by the server */
    private List<MacAlgorithm> serverSupportedMacAlgorithmsClientToServer;
    /** List of MAC algorithms (server to client) supported by the server */
    private List<MacAlgorithm> serverSupportedMacAlgorithmsServerToClient;
    /** List of compression algorithms (client to server) supported by the client */
    private List<CompressionAlgorithm> clientSupportedCompressionAlgorithmsClientToServer;
    /** List of compression algorithms (server to client) supported by the client */
    private List<CompressionAlgorithm> clientSupportedCompressionAlgorithmsServerToClient;
    /** List of compression algorithms (client to server) supported by the server */
    private List<CompressionAlgorithm> serverSupportedCompressionAlgorithmsClientToServer;
    /** List of compression algorithms (server to client) supported by the server */
    private List<CompressionAlgorithm> serverSupportedCompressionAlgorithmsServerToClient;
    /** List of languages (client to server) supported by the client */
    private List<String> clientSupportedLanguagesClientToServer;
    /** List of languages (server to client) supported by the client */
    private List<String> clientSupportedLanguagesServerToClient;
    /** List of languages (client to server) supported by the server */
    private List<String> serverSupportedLanguagesClientToServer;
    /** List of languages (server to client) supported by the server */
    private List<String> serverSupportedLanguagesServerToClient;
    /**
     * A boolean flag used to indicate that a guessed key exchange paket will be sent by the client
     */
    private Boolean clientFirstKeyExchangePacketFollows;
    /**
     * A boolean flag used to indicate that a guessed key exchange paket will be sent by the server
     */
    private Boolean serverFirstKeyExchangePacketFollows;
    /** Value of the clients' reserved field which may be used for extensions in the future */
    private Integer clientReserved;
    /** Value of the servers' reserved field which may be used for extensions in the future */
    private Integer serverReserved;
    // endregion

    // region Negotiated Parameters
    /** Negotiated key exchange algorithm */
    private KeyExchangeAlgorithm keyExchangeAlgorithm;
    /** Negotiated host key algorithm */
    private PublicKeyAuthenticationAlgorithm serverHostKeyAlgorithm;
    /** Negotiated cipher algorithm (client to server) */
    private EncryptionAlgorithm cipherAlgorithmClientToServer;
    /** Negotiated cipher algorithm (server to client) */
    private EncryptionAlgorithm cipherAlgorithmServerToClient;
    /** Negotiated MAC algorithm (client to server) */
    private MacAlgorithm macAlgorithmClientToServer;
    /** Negotiated MAC algorithm (server to client) */
    private MacAlgorithm macAlgorithmServerToClient;
    /** Negotiated compression algorithm (client to server) */
    private CompressionAlgorithm compressionAlgorithmClientToServer;
    /** Negotiated compression algorithm (server to client) */
    private CompressionAlgorithm compressionAlgorithmServerToClient;
    // endregion

    // region Key Exchange
    /**
     * An ongoing or already completed key exchange which can be used to generate a key pair or
     * compute the shared secret
     */
    private KeyExchange keyExchangeInstance;
    /** Type of the servers' host key */
    private PublicKeyAuthenticationAlgorithm hostKeyType;
    /** Host key of the server */
    // TODO: Implement host key as abstract class
    private byte[] serverHostKey;
    /** Signature generated by the server to authenticate the key exchange */
    private byte[] keyExchangeSignature;
    // endregion

    // region Exchange Hash and Cryptographic Keys
    /** Instance of the ExchangeHash class for exchange hash computation */
    private ExchangeHash exchangeHash;
    /**
     * Unique identifier for this session. This is equal to the first computed exchange hash and
     * never changes
     */
    private byte[] sessionID;
    /** Initial IV (client to server) derived from the shared secret during the protocol */
    private byte[] initialIvClientToServer;
    /** Initial IV (server to client) derived from the shared secret during the protocol */
    private byte[] initialIvServerToClient;
    /** Encryption key (client to server) derived from the shared secret during the protocol */
    private byte[] encryptionKeyClientToServer;
    /** Encryption key (server to client) derived from the shared secret during the protocol */
    private byte[] encryptionKeyServerToClient;
    /** Integrity key (client to server) derived from the shared secret during the protocol */
    private byte[] integrityKeyClientToServer;
    /** Integrity key (server to client) derived from the shared secret during the protocol */
    private byte[] integrityKeyServerToClient;
    // endregion

    // region Authentication Protocol
    /** Authentication method used to authenticate against the server */
    private AuthenticationMethod authenticationMethod;
    // endregion

    // region Connection Protocol
    // TODO: Implement connection protocol to support multiplexing
    /** Local channel identifier */
    private Integer localChannel;
    /** Remote channel identifier */
    private Integer remoteChannel;
    /**
     * Window size of the channel. The window size defines how many bytes the local peer may send
     * before the remote peer must send a SSH_MSG_CHANNEL_WINDOW_ADJUST to allow the local peer to
     * send more bytes. Whenever a packet is send, this number is decremented by the packets length.
     */
    private Integer windowSize;
    /** Maximum size of a single packet within the channel */
    private Integer packetSize;
    /** Type of the channel */
    private ChannelType channelType;
    // TODO: Implement channel requests in such a way that allows specification within the XML file
    // endregion

    /** If set to true, a SSH_MSG_DISCONNECT has been received from the remote peer */
    private boolean receivedDisconnectMessage = false;
    /** If set to true, a version exchange message was sent by each side */
    private boolean versionExchangeCompleted = false;

    // region Constructors and Initalization
    public SshContext() {
        this(Config.createConfig());
    }

    public SshContext(Config config) {
        RunningModeType mode = config.getDefaultRunningMode();
        if (mode == null) {
            throw new ConfigurationException("Cannot create connection, running mode not set");
        } else {
            switch (mode) {
                case CLIENT:
                    init(config, config.getDefaultClientConnection());
                    break;
                case SERVER:
                    init(config, config.getDefaultServerConnection());
                    break;
                default:
                    throw new ConfigurationException(
                            "Cannot create connection for unknown running mode '" + mode + "'");
            }
        }
    }

    public SshContext(Config config, AliasedConnection connection) {
        init(config, connection);
    }

    public void init(Config config, AliasedConnection connection) {
        this.config = config;
        this.connection = connection;
        exchangeHash = new ExchangeHash(this);

        // TODO: Initial packet layer type from config
        packetLayerType = PacketLayerType.BLOB;
        packetLayer = PacketLayerFactory.getPacketLayer(packetLayerType, this);
        writeSequenceNumber = 0;
        readSequenceNumber = 0;
    }

    // endregion

    public Config getConfig() {
        return config;
    }

    public Chooser getChooser() {
        if (chooser == null) {
            chooser = ChooserFactory.getChooser(config.getChooserType(), this, config);
        }
        return chooser;
    }

    public AliasedConnection getConnection() {
        return connection;
    }

    public void setConnection(AliasedConnection connection) {
        this.connection = connection;
    }

    public TransportHandler getTransportHandler() {
        return transportHandler;
    }

    public void setTransportHandler(TransportHandler transportHandler) {
        this.transportHandler = transportHandler;
    }

    public boolean hasReceivedTransportHandlerException() {
        return receivedTransportHandlerException;
    }

    public void setReceivedTransportHandlerException(boolean receivedTransportHandlerException) {
        this.receivedTransportHandlerException = receivedTransportHandlerException;
    }

    public void initTransportHandler() {
        if (transportHandler == null) {
            if (connection == null) {
                throw new ConfigurationException("Connection end not set");
            }
            transportHandler = TransportHandlerFactory.createTransportHandler(connection);
        }

        try {
            transportHandler.initialize();
        } catch (NullPointerException | NumberFormatException ex) {
            throw new ConfigurationException("Invalid values in " + connection.toString(), ex);
        } catch (IOException ex) {
            throw new TransportHandlerConnectException(
                    "Unable to initialize the transport handler with: " + connection.toString(),
                    ex);
        }
    }

    public PacketLayerType getPacketLayerType() {
        return packetLayerType;
    }

    public void setPacketLayerType(PacketLayerType packetLayerType) {
        this.packetLayerType = packetLayerType;
    }

    public AbstractPacketLayer getPacketLayer() {
        return packetLayer;
    }

    public void setPacketLayer(AbstractPacketLayer packetLayer) {
        this.packetLayer = packetLayer;
    }

    public MessageLayer getMessageLayer() {
        return messageLayer;
    }

    public void setMessageLayer(MessageLayer messageLayer) {
        this.messageLayer = messageLayer;
    }

    // region Getters and Setters for Sequence Numbers
    public int getWriteSequenceNumber() {
        return writeSequenceNumber;
    }

    public void setWriteSequenceNumber(int writeSequenceNumber) {
        this.writeSequenceNumber = writeSequenceNumber;
    }

    public void incrementWriteSequenceNumber() {
        incrementWriteSequenceNumber(1);
    }

    public void incrementWriteSequenceNumber(int i) {
        // Java does not support native unsigned integers :(
        writeSequenceNumber =
                (int)
                        ((Integer.toUnsignedLong(writeSequenceNumber) + Integer.toUnsignedLong(i))
                                % DataFormatConstants.UNSIGNED_INT_MAX_VALUE);
    }

    public int getReadSequenceNumber() {
        return readSequenceNumber;
    }

    public void setReadSequenceNumber(int readSequenceNumber) {
        this.readSequenceNumber = readSequenceNumber;
    }

    public void incrementReadSequenceNumber() {
        incrementReadSequenceNumber(1);
    }

    public void incrementReadSequenceNumber(int i) {
        // Java does not support native unsigned integers :(
        readSequenceNumber =
                (int)
                        ((Integer.toUnsignedLong(readSequenceNumber) + Integer.toUnsignedLong(i))
                                % DataFormatConstants.UNSIGNED_INT_MAX_VALUE);
    }

    // endregion

    // region Getters for Version Exchange Fields
    public Optional<String> getClientVersion() {
        return Optional.ofNullable(clientVersion);
    }

    public Optional<String> getClientComment() {
        return Optional.ofNullable(clientComment);
    }

    public Optional<String> getServerVersion() {
        return Optional.ofNullable(serverVersion);
    }

    public Optional<String> getServerComment() {
        return Optional.ofNullable(serverComment);
    }

    public Optional<byte[]> getClientCookie() {
        return Optional.ofNullable(clientCookie);
    }

    public Optional<byte[]> getServerCookie() {
        return Optional.ofNullable(serverCookie);
    }

    public Optional<String> getEndofMessageSequence() {
        return Optional.ofNullable(endofMessageSequence);
    }

    // endregion
    // region Setters for Version Exchange Fields
    public void setClientVersion(String clientVersion) {
        this.clientVersion = clientVersion;
    }

    public void setClientComment(String clientComment) {
        this.clientComment = clientComment;
    }

    public void setServerVersion(String serverVersion) {
        this.serverVersion = serverVersion;
    }

    public void setServerComment(String serverComment) {
        this.serverComment = serverComment;
    }

    public void setClientCookie(byte[] clientCookie) {
        this.clientCookie = clientCookie;
    }

    public void setServerCookie(byte[] serverCookie) {
        this.serverCookie = serverCookie;
    }

    public void setEndofMessageSequence(String endMessageSequence) {
        this.endofMessageSequence = endMessageSequence;
    }
    // endregion

    // region Getters for Key Exchange Initialization Fields
    public Optional<List<KeyExchangeAlgorithm>> getClientSupportedKeyExchangeAlgorithms() {
        return Optional.ofNullable(clientSupportedKeyExchangeAlgorithms);
    }

    public Optional<List<KeyExchangeAlgorithm>> getServerSupportedKeyExchangeAlgorithms() {
        return Optional.ofNullable(serverSupportedKeyExchangeAlgorithms);
    }

    public Optional<List<PublicKeyAuthenticationAlgorithm>> getClientSupportedHostKeyAlgorithms() {
        return Optional.ofNullable(clientSupportedHostKeyAlgorithms);
    }

    public Optional<List<PublicKeyAuthenticationAlgorithm>> getServerSupportedHostKeyAlgorithms() {
        return Optional.ofNullable(serverSupportedHostKeyAlgorithms);
    }

    public Optional<List<EncryptionAlgorithm>> getClientSupportedCipherAlgorithmsClientToServer() {
        return Optional.ofNullable(clientSupportedCipherAlgorithmsClientToServer);
    }

    public Optional<List<EncryptionAlgorithm>> getClientSupportedCipherAlgorithmsServerToClient() {
        return Optional.ofNullable(clientSupportedCipherAlgorithmsServerToClient);
    }

    public Optional<List<EncryptionAlgorithm>> getServerSupportedCipherAlgorithmsServerToClient() {
        return Optional.ofNullable(serverSupportedCipherAlgorithmsServerToClient);
    }

    public Optional<List<EncryptionAlgorithm>> getServerSupportedCipherAlgorithmsClientToServer() {
        return Optional.ofNullable(serverSupportedCipherAlgorithmsClientToServer);
    }

    public Optional<List<MacAlgorithm>> getClientSupportedMacAlgorithmsClientToServer() {
        return Optional.ofNullable(clientSupportedMacAlgorithmsClientToServer);
    }

    public Optional<List<MacAlgorithm>> getClientSupportedMacAlgorithmsServerToClient() {
        return Optional.ofNullable(clientSupportedMacAlgorithmsServerToClient);
    }

    public Optional<List<MacAlgorithm>> getServerSupportedMacAlgorithmsServerToClient() {
        return Optional.ofNullable(serverSupportedMacAlgorithmsServerToClient);
    }

    public Optional<List<MacAlgorithm>> getServerSupportedMacAlgorithmsClientToServer() {
        return Optional.ofNullable(serverSupportedMacAlgorithmsClientToServer);
    }

    public Optional<List<CompressionAlgorithm>>
            getClientSupportedCompressionAlgorithmsClientToServer() {
        return Optional.ofNullable(clientSupportedCompressionAlgorithmsClientToServer);
    }

    public Optional<List<CompressionAlgorithm>>
            getClientSupportedCompressionAlgorithmsServerToClient() {
        return Optional.ofNullable(clientSupportedCompressionAlgorithmsServerToClient);
    }

    public Optional<List<CompressionAlgorithm>>
            getServerSupportedCompressionAlgorithmsServerToClient() {
        return Optional.ofNullable(serverSupportedCompressionAlgorithmsServerToClient);
    }

    public Optional<List<CompressionAlgorithm>>
            getServerSupportedCompressionAlgorithmsClientToServer() {
        return Optional.ofNullable(serverSupportedCompressionAlgorithmsClientToServer);
    }

    public Optional<List<String>> getClientSupportedLanguagesClientToServer() {
        return Optional.ofNullable(clientSupportedLanguagesClientToServer);
    }

    public Optional<List<String>> getClientSupportedLanguagesServerToClient() {
        return Optional.ofNullable(clientSupportedLanguagesServerToClient);
    }

    public Optional<List<String>> getServerSupportedLanguagesServerToClient() {
        return Optional.ofNullable(serverSupportedLanguagesServerToClient);
    }

    public Optional<List<String>> getServerSupportedLanguagesClientToServer() {
        return Optional.ofNullable(serverSupportedLanguagesClientToServer);
    }

    public Optional<Boolean> getClientFirstKeyExchangePacketFollows() {
        return Optional.ofNullable(clientFirstKeyExchangePacketFollows);
    }

    public Optional<Boolean> getServerFirstKeyExchangePacketFollows() {
        return Optional.ofNullable(serverFirstKeyExchangePacketFollows);
    }

    public Optional<Integer> getClientReserved() {
        return Optional.ofNullable(clientReserved);
    }

    public Optional<Integer> getServerReserved() {
        return Optional.ofNullable(serverReserved);
    }

    // endregion
    // region Setters for Key Exchange Initialization Fields
    public void setClientSupportedKeyExchangeAlgorithms(
            List<KeyExchangeAlgorithm> clientSupportedKeyExchangeAlgorithms) {
        this.clientSupportedKeyExchangeAlgorithms = clientSupportedKeyExchangeAlgorithms;
    }

    public void setServerSupportedKeyExchangeAlgorithms(
            List<KeyExchangeAlgorithm> serverSupportedKeyExchangeAlgorithms) {
        this.serverSupportedKeyExchangeAlgorithms = serverSupportedKeyExchangeAlgorithms;
    }

    public void setClientSupportedHostKeyAlgorithms(
            List<PublicKeyAuthenticationAlgorithm> clientSupportedHostKeyAlgorithms) {
        this.clientSupportedHostKeyAlgorithms = clientSupportedHostKeyAlgorithms;
    }

    public void setServerSupportedHostKeyAlgorithms(
            List<PublicKeyAuthenticationAlgorithm> serverSupportedHostKeyAlgorithms) {
        this.serverSupportedHostKeyAlgorithms = serverSupportedHostKeyAlgorithms;
    }

    public void setClientSupportedCipherAlgorithmsClientToServer(
            List<EncryptionAlgorithm> clientSupportedCipherAlgorithmsClientToServer) {
        this.clientSupportedCipherAlgorithmsClientToServer =
                clientSupportedCipherAlgorithmsClientToServer;
    }

    public void setClientSupportedCipherAlgorithmsServerToClient(
            List<EncryptionAlgorithm> clientSupportedCipherAlgorithmsServerToClient) {
        this.clientSupportedCipherAlgorithmsServerToClient =
                clientSupportedCipherAlgorithmsServerToClient;
    }

    public void setServerSupportedCipherAlgorithmsServerToClient(
            List<EncryptionAlgorithm> serverSupportedCipherAlgorithmsServerToClient) {
        this.serverSupportedCipherAlgorithmsServerToClient =
                serverSupportedCipherAlgorithmsServerToClient;
    }

    public void setServerSupportedCipherAlgorithmsClientToServer(
            List<EncryptionAlgorithm> serverSupportedCipherAlgorithmsClientToServer) {
        this.serverSupportedCipherAlgorithmsClientToServer =
                serverSupportedCipherAlgorithmsClientToServer;
    }

    public void setClientSupportedMacAlgorithmsClientToServer(
            List<MacAlgorithm> clientSupportedMacAlgorithmsClientToServer) {
        this.clientSupportedMacAlgorithmsClientToServer =
                clientSupportedMacAlgorithmsClientToServer;
    }

    public void setClientSupportedMacAlgorithmsServerToClient(
            List<MacAlgorithm> clientSupportedMacAlgorithmsServerToClient) {
        this.clientSupportedMacAlgorithmsServerToClient =
                clientSupportedMacAlgorithmsServerToClient;
    }

    public void setServerSupportedMacAlgorithmsServerToClient(
            List<MacAlgorithm> serverSupportedMacAlgorithmsServerToClient) {
        this.serverSupportedMacAlgorithmsServerToClient =
                serverSupportedMacAlgorithmsServerToClient;
    }

    public void setServerSupportedMacAlgorithmsClientToServer(
            List<MacAlgorithm> serverSupportedMacAlgorithmsClientToServer) {
        this.serverSupportedMacAlgorithmsClientToServer =
                serverSupportedMacAlgorithmsClientToServer;
    }

    public void setClientSupportedCompressionAlgorithmsClientToServer(
            List<CompressionAlgorithm> clientSupportedCompressionAlgorithmsClientToServer) {
        this.clientSupportedCompressionAlgorithmsClientToServer =
                clientSupportedCompressionAlgorithmsClientToServer;
    }

    public void setClientSupportedCompressionAlgorithmsServerToClient(
            List<CompressionAlgorithm> clientSupportedCompressionAlgorithmsServerToClient) {
        this.clientSupportedCompressionAlgorithmsServerToClient =
                clientSupportedCompressionAlgorithmsServerToClient;
    }

    public void setServerSupportedCompressionAlgorithmsServerToClient(
            List<CompressionAlgorithm> serverSupportedCompressionAlgorithmsServerToClient) {
        this.serverSupportedCompressionAlgorithmsServerToClient =
                serverSupportedCompressionAlgorithmsServerToClient;
    }

    public void setServerSupportedCompressionAlgorithmsClientToServer(
            List<CompressionAlgorithm> serverSupportedCompressionAlgorithmsClientToServer) {
        this.serverSupportedCompressionAlgorithmsClientToServer =
                serverSupportedCompressionAlgorithmsClientToServer;
    }

    public void setClientSupportedLanguagesClientToServer(
            List<String> clientSupportedLanguagesClientToServer) {
        this.clientSupportedLanguagesClientToServer = clientSupportedLanguagesClientToServer;
    }

    public void setClientSupportedLanguagesServerToClient(
            List<String> clientSupportedLanguagesServerToClient) {
        this.clientSupportedLanguagesServerToClient = clientSupportedLanguagesServerToClient;
    }

    public void setServerSupportedLanguagesServerToClient(
            List<String> serverSupportedLanguagesServerToClient) {
        this.serverSupportedLanguagesServerToClient = serverSupportedLanguagesServerToClient;
    }

    public void setServerSupportedLanguagesClientToServer(
            List<String> serverSupportedLanguagesClientToServer) {
        this.serverSupportedLanguagesClientToServer = serverSupportedLanguagesClientToServer;
    }

    public void setClientFirstKeyExchangePacketFollows(
            boolean clientFirstKeyExchangePacketFollows) {
        this.clientFirstKeyExchangePacketFollows = clientFirstKeyExchangePacketFollows;
    }

    public void setServerFirstKeyExchangePacketFollows(
            boolean serverFirstKeyExchangePacketFollows) {
        this.serverFirstKeyExchangePacketFollows = serverFirstKeyExchangePacketFollows;
    }

    public void setClientReserved(int clientReserved) {
        this.clientReserved = clientReserved;
    }

    public void setServerReserved(int serverReserved) {
        this.serverReserved = serverReserved;
    }

    // endregion

    // region Getters for Negotiated Parameters
    public Optional<KeyExchangeAlgorithm> getKeyExchangeAlgorithm() {
        return Optional.ofNullable(keyExchangeAlgorithm);
    }

    public Optional<PublicKeyAuthenticationAlgorithm> getServerHostKeyAlgorithm() {
        return Optional.ofNullable(serverHostKeyAlgorithm);
    }

    public Optional<EncryptionAlgorithm> getCipherAlgorithmClientToServer() {
        return Optional.ofNullable(cipherAlgorithmClientToServer);
    }

    public Optional<EncryptionAlgorithm> getCipherAlgorithmServerToClient() {
        return Optional.ofNullable(cipherAlgorithmServerToClient);
    }

    public Optional<MacAlgorithm> getMacAlgorithmClientToServer() {
        return Optional.ofNullable(macAlgorithmClientToServer);
    }

    public Optional<MacAlgorithm> getMacAlgorithmServerToClient() {
        return Optional.ofNullable(macAlgorithmServerToClient);
    }

    public Optional<CompressionAlgorithm> getCompressionAlgorithmClientToServer() {
        return Optional.ofNullable(compressionAlgorithmClientToServer);
    }

    public Optional<CompressionAlgorithm> getCompressionAlgorithmServerToClient() {
        return Optional.ofNullable(compressionAlgorithmServerToClient);
    }

    // endregion
    // region Setters for Negotiated Parameters
    public void setKeyExchangeAlgorithm(KeyExchangeAlgorithm keyExchangeAlgorithm) {
        this.keyExchangeAlgorithm = keyExchangeAlgorithm;
    }

    public void setServerHostKeyAlgorithm(PublicKeyAuthenticationAlgorithm serverHostKeyAlgorithm) {
        this.serverHostKeyAlgorithm = serverHostKeyAlgorithm;
    }

    public void setCipherAlgorithmClientToServer(
            EncryptionAlgorithm cipherAlgorithmClientToServer) {
        this.cipherAlgorithmClientToServer = cipherAlgorithmClientToServer;
    }

    public void setCipherAlgorithmServerToClient(
            EncryptionAlgorithm cipherAlgorithmServerToClient) {
        this.cipherAlgorithmServerToClient = cipherAlgorithmServerToClient;
    }

    public void setMacAlgorithmClientToServer(MacAlgorithm macAlgorithmClientToServer) {
        this.macAlgorithmClientToServer = macAlgorithmClientToServer;
    }

    public void setMacAlgorithmServerToClient(MacAlgorithm macAlgorithmServerToClient) {
        this.macAlgorithmServerToClient = macAlgorithmServerToClient;
    }

    public void setCompressionAlgorithmClientToServer(
            CompressionAlgorithm compressionAlgorithmClientToServer) {
        this.compressionAlgorithmClientToServer = compressionAlgorithmClientToServer;
    }

    public void setCompressionAlgorithmServerToClient(
            CompressionAlgorithm compressionAlgorithmServerToClient) {
        this.compressionAlgorithmServerToClient = compressionAlgorithmServerToClient;
    }

    // endregion

    // region Getters for Key Exchange Fields
    public Optional<KeyExchange> getKeyExchangeInstance() {
        return Optional.ofNullable(keyExchangeInstance);
    }

    public Optional<PublicKeyAuthenticationAlgorithm> getHostKeyType() {
        return Optional.ofNullable(hostKeyType);
    }

    public Optional<byte[]> getServerHostKey() {
        return Optional.ofNullable(serverHostKey);
    }

    public Optional<byte[]> getKeyExchangeSignature() {
        return Optional.ofNullable(keyExchangeSignature);
    }

    // endregion
    // region Setters for Key Exchange Fields
    public void setKeyExchangeInstance(KeyExchange keyExchangeInstance) {
        this.keyExchangeInstance = keyExchangeInstance;
    }

    public void setHostKeyType(PublicKeyAuthenticationAlgorithm hostKeyType) {
        this.hostKeyType = hostKeyType;
    }

    public void setServerHostKey(byte[] serverHostKey) {
        this.serverHostKey = serverHostKey;
    }

    public void setKeyExchangeSignature(byte[] keyExchangeSignature) {
        this.keyExchangeSignature = keyExchangeSignature;
    }

    // endregion

    // region Getters for Exchange Hash and Cryptographic Keys
    public ExchangeHash getExchangeHashInstance() {
        return exchangeHash;
    }

    public Optional<byte[]> getSessionID() {
        return Optional.ofNullable(sessionID);
    }

    public Optional<byte[]> getInitialIvClientToServer() {
        return Optional.ofNullable(initialIvClientToServer);
    }

    public Optional<byte[]> getInitialIvServerToClient() {
        return Optional.ofNullable(initialIvServerToClient);
    }

    public Optional<byte[]> getEncryptionKeyClientToServer() {
        return Optional.ofNullable(encryptionKeyClientToServer);
    }

    public Optional<byte[]> getEncryptionKeyServerToClient() {
        return Optional.ofNullable(encryptionKeyServerToClient);
    }

    public Optional<byte[]> getIntegrityKeyClientToServer() {
        return Optional.ofNullable(integrityKeyClientToServer);
    }

    public Optional<byte[]> getIntegrityKeyServerToClient() {
        return Optional.ofNullable(integrityKeyServerToClient);
    }

    // endregion
    // region Setters for Exchange Hash and Cryptographic Keys
    public void setExchangeHashInstance(ExchangeHash exchangeHash) {
        this.exchangeHash = exchangeHash;
    }

    public void setSessionID(byte[] sessionID) {
        this.sessionID = sessionID;
    }

    public void setInitialIvClientToServer(byte[] initialIvClientToServer) {
        this.initialIvClientToServer = initialIvClientToServer;
    }

    public void setInitialIvServerToClient(byte[] initialIvServerToClient) {
        this.initialIvServerToClient = initialIvServerToClient;
    }

    public void setEncryptionKeyClientToServer(byte[] encryptionKeyClientToServer) {
        this.encryptionKeyClientToServer = encryptionKeyClientToServer;
    }

    public void setEncryptionKeyServerToClient(byte[] encryptionKeyServerToClient) {
        this.encryptionKeyServerToClient = encryptionKeyServerToClient;
    }

    public void setIntegrityKeyClientToServer(byte[] integrityKeyClientToServer) {
        this.integrityKeyClientToServer = integrityKeyClientToServer;
    }

    public void setIntegrityKeyServerToClient(byte[] integrityKeyServerToClient) {
        this.integrityKeyServerToClient = integrityKeyServerToClient;
    }

    // endregion

    // region Getters for Authentication Protocol Fields
    public Optional<AuthenticationMethod> getAuthenticationMethod() {
        return Optional.ofNullable(authenticationMethod);
    }

    // endregion
    // region Setters for Authentication Protocol Fields
    public void setAuthenticationMethod(AuthenticationMethod authenticationMethod) {
        this.authenticationMethod = authenticationMethod;
    }

    // endregion

    // region Getters for Connection Protocol Fields
    public Optional<Integer> getLocalChannel() {
        return Optional.ofNullable(localChannel);
    }

    public Optional<Integer> getRemoteChannel() {
        return Optional.ofNullable(remoteChannel);
    }

    public Optional<Integer> getWindowSize() {
        return Optional.ofNullable(windowSize);
    }

    public Optional<Integer> getPacketSize() {
        return Optional.ofNullable(packetSize);
    }

    public Optional<ChannelType> getChannelType() {
        return Optional.ofNullable(channelType);
    }

    // endregion
    // region Setters for Connection Protocol Fields
    public void setLocalChannel(int localChannel) {
        this.localChannel = localChannel;
    }

    public void setRemoteChannel(int remoteChannel) {
        this.remoteChannel = remoteChannel;
    }

    public void setWindowSize(int windowSize) {
        this.windowSize = windowSize;
    }

    public void setPacketSize(int packetSize) {
        this.packetSize = packetSize;
    }

    public void setChannelType(ChannelType channelType) {
        this.channelType = channelType;
    }
    // endregion

    public boolean getReceivedDisconnectMessage() {
        return receivedDisconnectMessage;
    }

    public void setReceivedDisconnectMessage(Boolean receivedDisconnectMessage) {
        this.receivedDisconnectMessage = receivedDisconnectMessage;
    }

    public boolean isVersionExchangeComplete() {
        return versionExchangeCompleted;
    }

    public void setVersionExchangeComplete(Boolean complete) {
        this.versionExchangeCompleted = complete;
    }

    public boolean isClient() {
        return connection.getLocalConnectionEndType() == ConnectionEndType.CLIENT;
    }

    public boolean isServer() {
        return connection.getLocalConnectionEndType() == ConnectionEndType.SERVER;
    }
}
