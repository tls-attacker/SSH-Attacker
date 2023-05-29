/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.layer.context;

import de.rub.nds.sshattacker.core.config.Config;
import de.rub.nds.sshattacker.core.constants.*;
import de.rub.nds.sshattacker.core.crypto.hash.ExchangeHashInputHolder;
import de.rub.nds.sshattacker.core.crypto.kex.AbstractEcdhKeyExchange;
import de.rub.nds.sshattacker.core.crypto.kex.DhKeyExchange;
import de.rub.nds.sshattacker.core.crypto.kex.HybridKeyExchange;
import de.rub.nds.sshattacker.core.crypto.kex.RsaKeyExchange;
import de.rub.nds.sshattacker.core.crypto.keys.SshPublicKey;
import de.rub.nds.sshattacker.core.exceptions.ConfigurationException;
import de.rub.nds.sshattacker.core.packet.cipher.keys.KeySet;
import de.rub.nds.sshattacker.core.packet.layer.AbstractPacketLayer;
import de.rub.nds.sshattacker.core.packet.layer.PacketLayerFactory;
import de.rub.nds.sshattacker.core.protocol.connection.Channel;
import de.rub.nds.sshattacker.core.protocol.connection.ChannelManager;
import de.rub.nds.sshattacker.core.state.Context;
import de.rub.nds.sshattacker.core.workflow.chooser.Chooser;
import de.rub.nds.sshattacker.core.workflow.chooser.ChooserFactory;
import de.rub.nds.tlsattacker.transport.ConnectionEndType;
import de.rub.nds.tlsattacker.transport.TransportHandler;
import java.util.HashMap;
import java.util.List;
import java.util.Optional;
import java.util.Random;

public class SshContext extends LayerContext {

    /** Static configuration for SSH-Attacker */
    private Chooser chooser;

    public Random getRandom() {
        return random;
    }

    public void setRandom(Random random) {
        this.random = random;
    }

    private Random random;

    /** Connection used to communicate with the remote peer */
    private TransportHandler transportHandler;
    /** If set to true, an exception was received from the transport handler */
    private boolean receivedTransportHandlerException = false;

    /** The currently active packet layer type */
    private PacketLayerType packetLayerType;
    /** A layer to serialize packets */
    private AbstractPacketLayer packetLayer;
    /**
     * If set to true, receive actions will read the incoming byte stream on a per line basis (each
     * line is terminated by LF).
     */
    private Boolean receiveAsciiModeEnabled;
    /** A layer to serialize messages */
    // private MessageLayer messageLayer = new MessageLayer(super.getContext());

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

    /**
     * If set to false, messages are handled as a server connection. handleAsClient is used to allow
     * handling messages as a different connection end type than the connection end type of the
     * fixed connection in the context. This is needed in the handling of mitm/proxy messages.
     */
    private boolean handleAsClient;

    // region Version Exchange
    /** Client protocol and software version string starting with the SSH version (SSH-2.0-...) */
    private String clientVersion;
    /** Client comment sent alongside protocol and software version */
    private String clientComment;
    /** End-of-message sequence of the clients' VersionExchangeMessage */
    private String clientEndOfMessageSequence;
    /** Server protocol and software version string starting with the SSH version (SSH-2.0-...) */
    private String serverVersion;
    /** Server comment sent alongside protocol and software version */
    private String serverComment;
    /** End-of-message sequence of the servers' VersionExchangeMessage */
    private String serverEndOfMessageSequence;

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
    private List<PublicKeyAlgorithm> clientSupportedHostKeyAlgorithms;
    /** List of host key algorithms supported by the server */
    private List<PublicKeyAlgorithm> serverSupportedHostKeyAlgorithms;
    /** List of encryption algorithms (client to server) supported by the client */
    private List<EncryptionAlgorithm> clientSupportedEncryptionAlgorithmsClientToServer;
    /** List of encryption algorithms (server to client) supported by the client */
    private List<EncryptionAlgorithm> clientSupportedEncryptionAlgorithmsServerToClient;
    /** List of encryption algorithms (client to server) supported by the server */
    private List<EncryptionAlgorithm> serverSupportedEncryptionAlgorithmsClientToServer;
    /** List of encryption algorithms (server to client) supported by the server */
    private List<EncryptionAlgorithm> serverSupportedEncryptionAlgorithmsServerToClient;
    /** List of MAC algorithms (client to server) supported by the client */
    private List<MacAlgorithm> clientSupportedMacAlgorithmsClientToServer;
    /** List of MAC algorithms (server to client) supported by the client */
    private List<MacAlgorithm> clientSupportedMacAlgorithmsServerToClient;
    /** List of MAC algorithms (client to server) supported by the server */
    private List<MacAlgorithm> serverSupportedMacAlgorithmsClientToServer;
    /** List of MAC algorithms (server to client) supported by the server */
    private List<MacAlgorithm> serverSupportedMacAlgorithmsServerToClient;
    /** List of compression algorithms (client to server) supported by the client */
    private List<CompressionMethod> clientSupportedCompressionMethodsClientToServer;
    /** List of compression algorithms (server to client) supported by the client */
    private List<CompressionMethod> clientSupportedCompressionMethodsServerToClient;
    /** List of compression algorithms (client to server) supported by the server */
    private List<CompressionMethod> serverSupportedCompressionMethodsClientToServer;
    /** List of compression algorithms (server to client) supported by the server */
    private List<CompressionMethod> serverSupportedCompressionMethodsServerToClient;
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
    private PublicKeyAlgorithm hostKeyAlgorithm;
    /** Negotiated encryption algorithm (client to server) */
    private EncryptionAlgorithm encryptionAlgorithmClientToServer;
    /** Negotiated encryption algorithm (server to client) */
    private EncryptionAlgorithm encryptionAlgorithmServerToClient;
    /** Negotiated MAC algorithm (client to server) */
    private MacAlgorithm macAlgorithmClientToServer;
    /** Negotiated MAC algorithm (server to client) */
    private MacAlgorithm macAlgorithmServerToClient;
    /** Negotiated compression algorithm (client to server) */
    private CompressionMethod compressionMethodClientToServer;
    /** Negotiated compression algorithm (server to client) */
    private CompressionMethod compressionMethodServerToClient;
    // endregion

    // region Key Exchange
    /** Key exchange instance for static DH key exchange method(s) */
    private DhKeyExchange dhKeyExchangeInstance;
    /** Key exchange instance for DH key exchange method(s) with group exchange */
    private DhKeyExchange dhGexKeyExchangeInstance;
    /** Key exchange instance for ECDH key exchange method(s) (incl. X curve ECDH) */
    private AbstractEcdhKeyExchange ecdhKeyExchangeInstance;
    /** Key exchange instance for RSA key exchange method(s) */
    private RsaKeyExchange rsaKeyExchangeInstance;
    /** Key exchange instance for Hybrid key exchange method(s) */
    private HybridKeyExchange hybridKeyExchangeInstance;
    /**
     * If set to true, the most recent group request received was of type
     * DhGexKeyExchangeOldRequestMessage
     */
    private boolean oldGroupRequestReceived = false;
    /** Minimal acceptable DH group size as reported in the SSH_MSG_KEX_DH_GEX_REQUEST message */
    private Integer minimalDhGroupSize;
    /** Preferred DH group size as reported in the SSH_MSG_KEX_DH_GEX_REQUEST message */
    private Integer preferredDhGroupSize;
    /** Maximal acceptable DH group size as reported in the SSH_MSG_KEX_DH_GEX_REQUEST message */
    private Integer maximalDhGroupSize;
    /** Host key */
    private SshPublicKey<?, ?> hostKey;
    /** Signature generated by the server over the exchange hash to authenticate the key exchange */
    private byte[] serverExchangeHashSignature;
    /** Flag indicating whether the server exchange hash signature is valid */
    private Boolean serverExchangeHashSignatureValid;
    // endregion

    // region Exchange Hash and Cryptographic Keys
    /** Holder instance for the exchange hash input values */
    private ExchangeHashInputHolder exchangeHashInputHolder;
    /** Exchange hash of the most recent key exchange */
    private byte[] exchangeHash;
    /**
     * Unique identifier for this session. This is equal to the first computed exchange hash and
     * never changes
     */
    private byte[] sessionID;
    /** The shared secret established by the negotiated key exchange method */
    private byte[] sharedSecret;
    /** The key set derived from the shared secret, the exchange hash, and the session ID */
    private KeySet keySet;
    // endregion

    // region Connection Protocol

    private ChannelManager channelManager;

    // TODO: Implement channel requests in such a way that allows specification within the XML file
    // endregion

    /** If set to true, a SSH_MSG_DISCONNECT has been received from the remote peer */
    private boolean disconnectMessageReceived = false;
    /** If set to true, a version exchange message was sent by each side */
    private boolean versionExchangeCompleted = false;

    private CompressionAlgorithm selectedCompressionAlgorithm;

    public CompressionAlgorithm getSelectedCompressionAlgorithm() {
        return selectedCompressionAlgorithm;
    }

    public void setSelectedCompressionAlgorithm(CompressionAlgorithm selectedCompressionAlgorithm) {
        this.selectedCompressionAlgorithm = selectedCompressionAlgorithm;
    }

    public EncryptionAlgorithm getSelectedEncryptionAlgorithm() {
        return selectedEncryptionAlgorithm;
    }

    public void setSelectedEncryptionAlgorithm(EncryptionAlgorithm selectedEncryptionAlgorithm) {
        this.selectedEncryptionAlgorithm = selectedEncryptionAlgorithm;
    }

    public MacAlgorithm getSelectedMacAlgorithm() {
        return selectedMacAlgorithm;
    }

    public void setSelectedMacAlgorithm(MacAlgorithm selectedMacAlgorithm) {
        this.selectedMacAlgorithm = selectedMacAlgorithm;
    }

    public KeyExchangeAlgorithm getSelectedKeyExchangeAlgorithm() {
        return selectedKeyExchangeAlgorithm;
    }

    public void setSelectedKeyExchangeAlgorithm(KeyExchangeAlgorithm selectedKeyExchangeAlgorithm) {
        this.selectedKeyExchangeAlgorithm = selectedKeyExchangeAlgorithm;
    }

    private EncryptionAlgorithm selectedEncryptionAlgorithm;
    private MacAlgorithm selectedMacAlgorithm;
    private KeyExchangeAlgorithm selectedKeyExchangeAlgorithm;

    // region Constructors and Initalization
    public SshContext() {
        this(new Context(new Config()));
    }

    public SshContext(Config config) {
        this(new Context(config));
    }

    public SshContext(Context context) {
        super(context);
        context.setSshContext(this);
        RunningModeType mode = getConfig().getDefaultRunningMode();
        if (null == mode) {
            throw new ConfigurationException("Cannot create connection, running mode not set");
        } else {
            init();
        }
    }

    public void init() {
        exchangeHashInputHolder = new ExchangeHashInputHolder();

        // TODO: Initial packet layer type from config
        packetLayerType = PacketLayerType.BLOB;
        packetLayer = PacketLayerFactory.getPacketLayer(packetLayerType, this);
        receiveAsciiModeEnabled = true;
        writeSequenceNumber = 0;
        readSequenceNumber = 0;
        handleAsClient = (getConnection().getLocalConnectionEndType() == ConnectionEndType.CLIENT);
        channelManager = new ChannelManager(this);
    }

    // endregion

    public Chooser getChooser() {
        if (chooser == null) {
            chooser =
                    ChooserFactory.getChooser(
                            getConfig().getChooserType(), this.getContext(), getConfig());
        }
        return chooser;
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

    public Boolean isReceiveAsciiModeEnabled() {
        return receiveAsciiModeEnabled;
    }

    public void setReceiveAsciiModeEnabled(boolean receiveAsciiModeEnabled) {
        this.receiveAsciiModeEnabled = receiveAsciiModeEnabled;
    }

    /*public MessageLayer getMessageLayer() {
        return messageLayer;
    }

    public void setMessageLayer(MessageLayer messageLayer) {
        this.messageLayer = messageLayer;
    }*/

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

    public Optional<String> getClientEndOfMessageSequence() {
        return Optional.ofNullable(clientEndOfMessageSequence);
    }

    public Optional<String> getServerVersion() {
        return Optional.ofNullable(serverVersion);
    }

    public Optional<String> getServerComment() {
        return Optional.ofNullable(serverComment);
    }

    public Optional<String> getServerEndOfMessageSequence() {
        return Optional.ofNullable(serverEndOfMessageSequence);
    }

    // endregion
    // region Setters for Version Exchange Fields
    public void setClientVersion(String clientVersion) {
        this.clientVersion = clientVersion;
    }

    public void setClientComment(String clientComment) {
        this.clientComment = clientComment;
    }

    public void setClientEndOfMessageSequence(String clientEndOfMessageSequence) {
        this.clientEndOfMessageSequence = clientEndOfMessageSequence;
    }

    public void setServerVersion(String serverVersion) {
        this.serverVersion = serverVersion;
    }

    public void setServerComment(String serverComment) {
        this.serverComment = serverComment;
    }

    public void setServerEndOfMessageSequence(String serverEndOfMessageSequence) {
        this.serverEndOfMessageSequence = serverEndOfMessageSequence;
    }
    // endregion

    // region Getters for Key Exchange Initialization Fields
    public Optional<byte[]> getClientCookie() {
        return Optional.ofNullable(clientCookie);
    }

    public Optional<byte[]> getServerCookie() {
        return Optional.ofNullable(serverCookie);
    }

    public Optional<List<KeyExchangeAlgorithm>> getClientSupportedKeyExchangeAlgorithms() {
        return Optional.ofNullable(clientSupportedKeyExchangeAlgorithms);
    }

    public Optional<List<KeyExchangeAlgorithm>> getServerSupportedKeyExchangeAlgorithms() {
        return Optional.ofNullable(serverSupportedKeyExchangeAlgorithms);
    }

    public Optional<List<PublicKeyAlgorithm>> getClientSupportedHostKeyAlgorithms() {
        return Optional.ofNullable(clientSupportedHostKeyAlgorithms);
    }

    public Optional<List<PublicKeyAlgorithm>> getServerSupportedHostKeyAlgorithms() {
        return Optional.ofNullable(serverSupportedHostKeyAlgorithms);
    }

    public Optional<List<EncryptionAlgorithm>>
            getClientSupportedEncryptionAlgorithmsClientToServer() {
        return Optional.ofNullable(clientSupportedEncryptionAlgorithmsClientToServer);
    }

    public Optional<List<EncryptionAlgorithm>>
            getClientSupportedEncryptionAlgorithmsServerToClient() {
        return Optional.ofNullable(clientSupportedEncryptionAlgorithmsServerToClient);
    }

    public Optional<List<EncryptionAlgorithm>>
            getServerSupportedEncryptionAlgorithmsServerToClient() {
        return Optional.ofNullable(serverSupportedEncryptionAlgorithmsServerToClient);
    }

    public Optional<List<EncryptionAlgorithm>>
            getServerSupportedEncryptionAlgorithmsClientToServer() {
        return Optional.ofNullable(serverSupportedEncryptionAlgorithmsClientToServer);
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

    public Optional<List<CompressionMethod>> getClientSupportedCompressionMethodsClientToServer() {
        return Optional.ofNullable(clientSupportedCompressionMethodsClientToServer);
    }

    public Optional<List<CompressionMethod>> getClientSupportedCompressionMethodsServerToClient() {
        return Optional.ofNullable(clientSupportedCompressionMethodsServerToClient);
    }

    public Optional<List<CompressionMethod>> getServerSupportedCompressionMethodsServerToClient() {
        return Optional.ofNullable(serverSupportedCompressionMethodsServerToClient);
    }

    public Optional<List<CompressionMethod>> getServerSupportedCompressionMethodsClientToServer() {
        return Optional.ofNullable(serverSupportedCompressionMethodsClientToServer);
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
    public void setClientCookie(byte[] clientCookie) {
        this.clientCookie = clientCookie;
    }

    public void setServerCookie(byte[] serverCookie) {
        this.serverCookie = serverCookie;
    }

    public void setClientSupportedKeyExchangeAlgorithms(
            List<KeyExchangeAlgorithm> clientSupportedKeyExchangeAlgorithms) {
        this.clientSupportedKeyExchangeAlgorithms = clientSupportedKeyExchangeAlgorithms;
    }

    public void setServerSupportedKeyExchangeAlgorithms(
            List<KeyExchangeAlgorithm> serverSupportedKeyExchangeAlgorithms) {
        this.serverSupportedKeyExchangeAlgorithms = serverSupportedKeyExchangeAlgorithms;
    }

    public void setClientSupportedHostKeyAlgorithms(
            List<PublicKeyAlgorithm> clientSupportedHostKeyAlgorithms) {
        this.clientSupportedHostKeyAlgorithms = clientSupportedHostKeyAlgorithms;
    }

    public void setServerSupportedHostKeyAlgorithms(
            List<PublicKeyAlgorithm> serverSupportedHostKeyAlgorithms) {
        this.serverSupportedHostKeyAlgorithms = serverSupportedHostKeyAlgorithms;
    }

    public void setClientSupportedEncryptionAlgorithmsClientToServer(
            List<EncryptionAlgorithm> clientSupportedEncryptionAlgorithmsClientToServer) {
        this.clientSupportedEncryptionAlgorithmsClientToServer =
                clientSupportedEncryptionAlgorithmsClientToServer;
    }

    public void setClientSupportedEncryptionAlgorithmsServerToClient(
            List<EncryptionAlgorithm> clientSupportedEncryptionAlgorithmsServerToClient) {
        this.clientSupportedEncryptionAlgorithmsServerToClient =
                clientSupportedEncryptionAlgorithmsServerToClient;
    }

    public void setServerSupportedEncryptionAlgorithmsServerToClient(
            List<EncryptionAlgorithm> serverSupportedEncryptionAlgorithmsServerToClient) {
        this.serverSupportedEncryptionAlgorithmsServerToClient =
                serverSupportedEncryptionAlgorithmsServerToClient;
    }

    public void setServerSupportedEncryptionAlgorithmsClientToServer(
            List<EncryptionAlgorithm> serverSupportedEncryptionAlgorithmsClientToServer) {
        this.serverSupportedEncryptionAlgorithmsClientToServer =
                serverSupportedEncryptionAlgorithmsClientToServer;
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

    public void setClientSupportedCompressionMethodsClientToServer(
            List<CompressionMethod> clientSupportedCompressionMethodsClientToServer) {
        this.clientSupportedCompressionMethodsClientToServer =
                clientSupportedCompressionMethodsClientToServer;
    }

    public void setClientSupportedCompressionMethodsServerToClient(
            List<CompressionMethod> clientSupportedCompressionMethodsServerToClient) {
        this.clientSupportedCompressionMethodsServerToClient =
                clientSupportedCompressionMethodsServerToClient;
    }

    public void setServerSupportedCompressionMethodsServerToClient(
            List<CompressionMethod> serverSupportedCompressionMethodsServerToClient) {
        this.serverSupportedCompressionMethodsServerToClient =
                serverSupportedCompressionMethodsServerToClient;
    }

    public void setServerSupportedCompressionMethodsClientToServer(
            List<CompressionMethod> serverSupportedCompressionMethodsClientToServer) {
        this.serverSupportedCompressionMethodsClientToServer =
                serverSupportedCompressionMethodsClientToServer;
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

    public Optional<PublicKeyAlgorithm> getHostKeyAlgorithm() {
        return Optional.ofNullable(hostKeyAlgorithm);
    }

    public Optional<EncryptionAlgorithm> getEncryptionAlgorithmClientToServer() {
        return Optional.ofNullable(encryptionAlgorithmClientToServer);
    }

    public Optional<EncryptionAlgorithm> getEncryptionAlgorithmServerToClient() {
        return Optional.ofNullable(encryptionAlgorithmServerToClient);
    }

    public Optional<MacAlgorithm> getMacAlgorithmClientToServer() {
        return Optional.ofNullable(macAlgorithmClientToServer);
    }

    public Optional<MacAlgorithm> getMacAlgorithmServerToClient() {
        return Optional.ofNullable(macAlgorithmServerToClient);
    }

    public Optional<CompressionMethod> getCompressionMethodClientToServer() {
        return Optional.ofNullable(compressionMethodClientToServer);
    }

    public Optional<CompressionMethod> getCompressionMethodServerToClient() {
        return Optional.ofNullable(compressionMethodServerToClient);
    }

    // endregion
    // region Setters for Negotiated Parameters
    public void setKeyExchangeAlgorithm(KeyExchangeAlgorithm keyExchangeAlgorithm) {
        this.keyExchangeAlgorithm = keyExchangeAlgorithm;
    }

    public void setHostKeyAlgorithm(PublicKeyAlgorithm hostKeyAlgorithm) {
        this.hostKeyAlgorithm = hostKeyAlgorithm;
    }

    public void setEncryptionAlgorithmClientToServer(
            EncryptionAlgorithm encryptionAlgorithmClientToServer) {
        this.encryptionAlgorithmClientToServer = encryptionAlgorithmClientToServer;
    }

    public void setEncryptionAlgorithmServerToClient(
            EncryptionAlgorithm encryptionAlgorithmServerToClient) {
        this.encryptionAlgorithmServerToClient = encryptionAlgorithmServerToClient;
    }

    public void setMacAlgorithmClientToServer(MacAlgorithm macAlgorithmClientToServer) {
        this.macAlgorithmClientToServer = macAlgorithmClientToServer;
    }

    public void setMacAlgorithmServerToClient(MacAlgorithm macAlgorithmServerToClient) {
        this.macAlgorithmServerToClient = macAlgorithmServerToClient;
    }

    public void setCompressionMethodClientToServer(
            CompressionMethod compressionMethodClientToServer) {
        this.compressionMethodClientToServer = compressionMethodClientToServer;
    }

    public void setCompressionMethodServerToClient(
            CompressionMethod compressionMethodServerToClient) {
        this.compressionMethodServerToClient = compressionMethodServerToClient;
    }

    // endregion

    // region Getters for Key Exchange Fields
    public Optional<DhKeyExchange> getDhKeyExchangeInstance() {
        return Optional.ofNullable(dhKeyExchangeInstance);
    }

    public Optional<DhKeyExchange> getDhGexKeyExchangeInstance() {
        return Optional.ofNullable(dhGexKeyExchangeInstance);
    }

    public Optional<AbstractEcdhKeyExchange> getEcdhKeyExchangeInstance() {
        return Optional.ofNullable(ecdhKeyExchangeInstance);
    }

    public Optional<HybridKeyExchange> getHybridKeyExchangeInstance() {
        return Optional.ofNullable(hybridKeyExchangeInstance);
    }

    public Optional<RsaKeyExchange> getRsaKeyExchangeInstance() {
        return Optional.ofNullable(rsaKeyExchangeInstance);
    }

    public boolean isOldGroupRequestReceived() {
        return oldGroupRequestReceived;
    }

    public Optional<Integer> getMinimalDhGroupSize() {
        return Optional.ofNullable(minimalDhGroupSize);
    }

    public Optional<Integer> getPreferredDhGroupSize() {
        return Optional.ofNullable(preferredDhGroupSize);
    }

    public Optional<Integer> getMaximalDhGroupSize() {
        return Optional.ofNullable(maximalDhGroupSize);
    }

    public Optional<SshPublicKey<?, ?>> getHostKey() {
        return Optional.ofNullable(hostKey);
    }

    public Optional<byte[]> getServerExchangeHashSignature() {
        return Optional.ofNullable(serverExchangeHashSignature);
    }

    public Optional<Boolean> isServerExchangeHashSignatureValid() {
        return Optional.ofNullable(serverExchangeHashSignatureValid);
    }
    // endregion
    // region Setters for Key Exchange Fields
    public void setDhKeyExchangeInstance(DhKeyExchange dhKeyExchangeInstance) {
        this.dhKeyExchangeInstance = dhKeyExchangeInstance;
    }

    public void setDhGexKeyExchangeInstance(DhKeyExchange dhGexKeyExchangeInstance) {
        this.dhGexKeyExchangeInstance = dhGexKeyExchangeInstance;
    }

    public void setEcdhKeyExchangeInstance(AbstractEcdhKeyExchange ecdhKeyExchangeInstance) {
        this.ecdhKeyExchangeInstance = ecdhKeyExchangeInstance;
    }

    public void setHybridKeyExchangeInstance(HybridKeyExchange HybridKeyExchangeInstance) {
        this.hybridKeyExchangeInstance = HybridKeyExchangeInstance;
    }

    public void setRsaKeyExchangeInstance(RsaKeyExchange rsaKeyExchangeInstance) {
        this.rsaKeyExchangeInstance = rsaKeyExchangeInstance;
    }

    public void setOldGroupRequestReceived(boolean oldGroupRequestReceived) {
        this.oldGroupRequestReceived = oldGroupRequestReceived;
    }

    public void setMinimalDhGroupSize(Integer minimalDhGroupSize) {
        this.minimalDhGroupSize = minimalDhGroupSize;
    }

    public void setPreferredDhGroupSize(Integer preferredDhGroupSize) {
        this.preferredDhGroupSize = preferredDhGroupSize;
    }

    public void setMaximalDhGroupSize(Integer maximalDhGroupSize) {
        this.maximalDhGroupSize = maximalDhGroupSize;
    }

    public void setHostKey(SshPublicKey<?, ?> hostKey) {
        this.hostKey = hostKey;
    }

    public void setServerExchangeHashSignature(byte[] serverExchangeHashSignature) {
        this.serverExchangeHashSignature = serverExchangeHashSignature;
    }

    public void setServerExchangeHashSignatureValid(Boolean isValid) {
        this.serverExchangeHashSignatureValid = isValid;
    }
    // endregion

    // region Getters for Exchange Hash and Cryptographic Keys
    public ExchangeHashInputHolder getExchangeHashInputHolder() {
        return exchangeHashInputHolder;
    }

    public Optional<byte[]> getExchangeHash() {
        return Optional.ofNullable(exchangeHash);
    }

    public Optional<byte[]> getSessionID() {
        return Optional.ofNullable(sessionID);
    }

    public Optional<byte[]> getSharedSecret() {
        return Optional.ofNullable(sharedSecret);
    }

    public Optional<KeySet> getKeySet() {
        return Optional.ofNullable(keySet);
    }
    // endregion
    // region Setters for Exchange Hash and Cryptographic Keys
    public void setExchangeHash(byte[] exchangeHash) {
        this.exchangeHash = exchangeHash;
    }

    public void setSessionID(byte[] sessionID) {
        this.sessionID = sessionID;
    }

    public void setSharedSecret(byte[] sharedSecret) {
        this.sharedSecret = sharedSecret;
    }

    public void setKeySet(KeySet transportKeySet) {
        this.keySet = transportKeySet;
    }
    // endregion

    // region for Connection Protocol Fields
    public HashMap<Integer, Channel> getChannels() {
        return channelManager.getChannels();
    }

    public ChannelManager getChannelManager() {
        return channelManager;
    }

    public void setChannelManager(ChannelManager channelManager) {
        this.channelManager = channelManager;
    }
    // endregion

    public boolean isDisconnectMessageReceived() {
        return disconnectMessageReceived;
    }

    public void setDisconnectMessageReceived(Boolean disconnectMessageReceived) {
        this.disconnectMessageReceived = disconnectMessageReceived;
    }

    public boolean isVersionExchangeComplete() {
        return versionExchangeCompleted;
    }

    public void setVersionExchangeComplete(Boolean complete) {
        this.versionExchangeCompleted = complete;
    }

    public boolean isClient() {
        return getConnection().getLocalConnectionEndType() == ConnectionEndType.CLIENT;
    }

    public boolean isServer() {
        return getConnection().getLocalConnectionEndType() == ConnectionEndType.SERVER;
    }

    public boolean isHandleAsClient() {
        return handleAsClient;
    }

    public void setHandleAsClient(boolean handleAsClient) {
        this.handleAsClient = handleAsClient;
    }
}
