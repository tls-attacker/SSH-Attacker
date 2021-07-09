/**
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2021 Ruhr University Bochum, Paderborn University,
 * and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.state;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.sshattacker.core.config.Config;
import de.rub.nds.sshattacker.core.constants.*;
import de.rub.nds.sshattacker.core.connection.AliasedConnection;
import de.rub.nds.sshattacker.core.crypto.KeyExchange;
import de.rub.nds.sshattacker.core.protocol.layers.BinaryPacketLayer;
import de.rub.nds.sshattacker.core.protocol.layers.CryptoLayer;
import de.rub.nds.sshattacker.core.protocol.layers.MessageLayer;
import de.rub.nds.sshattacker.core.util.Converter;
import de.rub.nds.tlsattacker.transport.tcp.ClientTcpTransportHandler;
import de.rub.nds.tlsattacker.transport.TransportHandler;

import java.io.IOException;
import java.math.BigInteger;
import java.util.List;
import java.util.Optional;

public class SshContext {

    private Config config;
    private Chooser chooser;

    private AliasedConnection connection;
    private TransportHandler transportHandler;
    private boolean receivedTransportHandlerException = false;

    private BinaryPacketLayer binaryPacketLayer = new BinaryPacketLayer(this);
    private MessageLayer messageLayer = new MessageLayer(this);
    private CryptoLayer cryptoLayerClientToServer;
    private CryptoLayer cryptoLayerServerToClient;

    private byte[] exchangeHashInput;
    private byte[] exchangeHash;
    private byte[] sessionID;

    private byte[] initialIvClientToServer;
    private byte[] initialIvServerToClient;

    private byte[] encryptionKeyClientToServer;
    private byte[] encryptionKeyServerToClient;

    private byte[] integrityKeyClientToServer;
    private byte[] integrityKeyServerToClient;

    private int sequenceNumber = 0;

    private String hostKeyType;
    private byte[] serverHostKey;
    private BigInteger hostKeyRsaExponent;
    private BigInteger hostKeyRsaModulus;
    private byte[] keyExchangeSignature;

    private KeyExchange keyExchangeInstance;

    /**
     * selected algorithms for this connection
     */
    private KeyExchangeAlgorithm keyExchangeAlgorithm;
    private PublicKeyAuthenticationAlgorithm serverHostKeyAlgorithm;

    private EncryptionAlgorithm cipherAlgorithmClientToServer;
    private EncryptionAlgorithm cipherAlgorithmServerToClient;

    private MacAlgorithm macAlgorithmClientToServer;
    private MacAlgorithm macAlgorithmServerToClient;

    private CompressionAlgorithm compressionAlgorithmClientToServer;
    private CompressionAlgorithm compressionAlgorithmServerToClient;

    private Language languageClientToServer;
    private Language languageServerToClient;

    private String clientVersion;
    private String clientComment;
    private String serverVersion;
    private String serverComment;
    private byte[] clientCookie;
    private byte[] serverCookie;
    private List<KeyExchangeAlgorithm> clientSupportedKeyExchangeAlgorithms;
    private List<KeyExchangeAlgorithm> serverSupportedKeyExchangeAlgorithms;
    private List<PublicKeyAuthenticationAlgorithm> clientSupportedHostKeyAlgorithms;
    private List<PublicKeyAuthenticationAlgorithm> serverSupportedHostKeyAlgorithms;
    private List<EncryptionAlgorithm> clientSupportedCipherAlgorithmsClientToServer;
    private List<EncryptionAlgorithm> clientSupportedCipherAlgorithmsServerToClient;
    private List<EncryptionAlgorithm> serverSupportedCipherAlgorithmsServerToClient;
    private List<EncryptionAlgorithm> serverSupportedCipherAlgorithmsClientToServer;
    private List<MacAlgorithm> clientSupportedMacAlgorithmsClientToServer;
    private List<MacAlgorithm> clientSupportedMacAlgorithmsServerToClient;
    private List<MacAlgorithm> serverSupportedMacAlgorithmsServerToClient;
    private List<MacAlgorithm> serverSupportedMacAlgorithmsClientToServer;
    private List<CompressionAlgorithm> clientSupportedCompressionAlgorithmsClientToServer;
    private List<CompressionAlgorithm> clientSupportedCompressionAlgorithmsServerToClient;
    private List<CompressionAlgorithm> serverSupportedCompressionAlgorithmsServerToClient;
    private List<CompressionAlgorithm> serverSupportedCompressionAlgorithmsClientToServer;
    private List<Language> clientSupportedLanguagesClientToServer;
    private List<Language> clientSupportedLanguagesServerToClient;
    private List<Language> serverSupportedLanguagesServerToClient;
    private List<Language> serverSupportedLanguagesClientToServer;
    private Byte clientFirstKeyExchangePacketFollows;
    private Byte serverFirstKeyExchangePacketFollows;
    private Integer clientReserved;
    private Integer serverReserved;

    private AuthenticationMethod authenticationMethod;
    private String serviceName;
    private String username;
    private String password;
    private int localChannel;
    private int remoteChannel;
    private int windowSize;
    private int packetSize;
    private ChannelType channelType;
    private ChannelRequestType channelRequestType;
    private String channelCommand;
    private byte replyWanted;

    private boolean receivedDisconnectMessage = false;
    private boolean isEncryptionActive = false;
    private boolean versionExchangeCompleted = false;
    private boolean keyExchangeCompleted = false;

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

    public Optional<List<EncryptionAlgorithm>> getClientSupportedCipherAlgorithmsServertoClient() {
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

    public Optional<List<CompressionAlgorithm>> getClientSupportedCompressionAlgorithmsClientToServer() {
        return Optional.ofNullable(clientSupportedCompressionAlgorithmsClientToServer);
    }

    public Optional<List<CompressionAlgorithm>> getClientSupportedCompressionAlgorithmsServerToClient() {
        return Optional.ofNullable(clientSupportedCompressionAlgorithmsServerToClient);
    }

    public Optional<List<CompressionAlgorithm>> getServerSupportedCompressionAlgorithmsServerToClient() {
        return Optional.ofNullable(serverSupportedCompressionAlgorithmsServerToClient);
    }

    public Optional<List<CompressionAlgorithm>> getServerSupportedCompressionAlgorithmsClientToServer() {
        return Optional.ofNullable(serverSupportedCompressionAlgorithmsClientToServer);
    }

    public Optional<List<Language>> getClientSupportedLanguagesClientToServer() {
        return Optional.ofNullable(clientSupportedLanguagesClientToServer);
    }

    public Optional<List<Language>> getClientSupportedLanguagesServerToClient() {
        return Optional.ofNullable(clientSupportedLanguagesServerToClient);
    }

    public Optional<List<Language>> getServerSupportedLanguagesServerToClient() {
        return Optional.ofNullable(serverSupportedLanguagesServerToClient);
    }

    public Optional<List<Language>> getServerSupportedLanguagesClientToServer() {
        return Optional.ofNullable(serverSupportedLanguagesClientToServer);
    }

    public Optional<Byte> getClientFirstKeyExchangePacketFollows() {
        return Optional.ofNullable(clientFirstKeyExchangePacketFollows);
    }

    public Optional<Byte> getServerFirstKeyExchangePacketFollows() {
        return Optional.ofNullable(serverFirstKeyExchangePacketFollows);
    }

    public Optional<Integer> getClientReserved() {
        return Optional.ofNullable(clientReserved);
    }

    public Optional<Integer> getServerReserved() {
        return Optional.ofNullable(serverReserved);
    }

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

    public void setClientSupportedKeyExchangeAlgorithms(List<KeyExchangeAlgorithm> clientSupportedKeyExchangeAlgorithms) {
        this.clientSupportedKeyExchangeAlgorithms = clientSupportedKeyExchangeAlgorithms;
    }

    public void setServerSupportedKeyExchangeAlgorithms(List<KeyExchangeAlgorithm> serverSupportedKeyExchangeAlgorithms) {
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
        this.clientSupportedCipherAlgorithmsClientToServer = clientSupportedCipherAlgorithmsClientToServer;
    }

    public void setClientSupportedCipherAlgorithmsServerToClient(
            List<EncryptionAlgorithm> clientSupportedCipherAlgorithmsServerToClient) {
        this.clientSupportedCipherAlgorithmsServerToClient = clientSupportedCipherAlgorithmsServerToClient;
    }

    public void setServerSupportedCipherAlgorithmsServerToClient(
            List<EncryptionAlgorithm> serverSupportedCipherAlgorithmsServerToClient) {
        this.serverSupportedCipherAlgorithmsServerToClient = serverSupportedCipherAlgorithmsServerToClient;
    }

    public void setServerSupportedCipherAlgorithmsClientToServer(
            List<EncryptionAlgorithm> serverSupportedCipherAlgorithmsClientToServer) {
        this.serverSupportedCipherAlgorithmsClientToServer = serverSupportedCipherAlgorithmsClientToServer;
    }

    public void setClientSupportedMacAlgorithmsClientToServer(
            List<MacAlgorithm> clientSupportedMacAlgorithmsClientToServer) {
        this.clientSupportedMacAlgorithmsClientToServer = clientSupportedMacAlgorithmsClientToServer;
    }

    public void setClientSupportedMacAlgorithmsServerToClient(
            List<MacAlgorithm> clientSupportedMacAlgorithmsServerToClient) {
        this.clientSupportedMacAlgorithmsServerToClient = clientSupportedMacAlgorithmsServerToClient;
    }

    public void setServerSupportedMacAlgorithmsServerToClient(
            List<MacAlgorithm> serverSupportedMacAlgorithmsServerToClient) {
        this.serverSupportedMacAlgorithmsServerToClient = serverSupportedMacAlgorithmsServerToClient;
    }

    public void setServerSupportedMacAlgorithmsClientToServer(
            List<MacAlgorithm> serverSupportedMacAlgorithmsClientToServer) {
        this.serverSupportedMacAlgorithmsClientToServer = serverSupportedMacAlgorithmsClientToServer;
    }

    public void setClientSupportedCompressionAlgorithmsClientToServer(
            List<CompressionAlgorithm> clientSupportedCompressionAlgorithmsClientToServer) {
        this.clientSupportedCompressionAlgorithmsClientToServer = clientSupportedCompressionAlgorithmsClientToServer;
    }

    public void setClientSupportedCompressionAlgorithmsServerToClient(
            List<CompressionAlgorithm> clientSupportedCompressionAlgorithmsServerToClient) {
        this.clientSupportedCompressionAlgorithmsServerToClient = clientSupportedCompressionAlgorithmsServerToClient;
    }

    public void setServerSupportedCompressionAlgorithmsServerToClient(
            List<CompressionAlgorithm> serverSupportedCompressionAlgorithmsServerToClient) {
        this.serverSupportedCompressionAlgorithmsServerToClient = serverSupportedCompressionAlgorithmsServerToClient;
    }

    public void setServerSupportedCompressionAlgorithmsClientToServer(
            List<CompressionAlgorithm> serverSupportedCompressionAlgorithmsClientToServer) {
        this.serverSupportedCompressionAlgorithmsClientToServer = serverSupportedCompressionAlgorithmsClientToServer;
    }

    public void setClientSupportedLanguagesClientToServer(List<Language> clientSupportedLanguagesClientToServer) {
        this.clientSupportedLanguagesClientToServer = clientSupportedLanguagesClientToServer;
    }

    public void setClientSupportedLanguagesServerToClient(List<Language> clientSupportedLanguagesServerToClient) {
        this.clientSupportedLanguagesServerToClient = clientSupportedLanguagesServerToClient;
    }

    public void setServerSupportedLanguagesServerToClient(List<Language> serverSupportedLanguagesServerToClient) {
        this.serverSupportedLanguagesServerToClient = serverSupportedLanguagesServerToClient;
    }

    public void setServerSupportedLanguagesClientToServer(List<Language> serverSupportedLanguagesClientToServer) {
        this.serverSupportedLanguagesClientToServer = serverSupportedLanguagesClientToServer;
    }

    public void setClientFirstKeyExchangePacketFollows(byte clientFirstKeyExchangePacketFollows) {
        this.clientFirstKeyExchangePacketFollows = clientFirstKeyExchangePacketFollows;
    }

    public void setServerFirstKeyExchangePacketFollows(byte serverFirstKeyExchangePacketFollows) {
        this.serverFirstKeyExchangePacketFollows = serverFirstKeyExchangePacketFollows;
    }

    public void setClientReserved(int clientReserved) {
        this.clientReserved = clientReserved;
    }

    public void setServerReserved(int serverReserved) {
        this.serverReserved = serverReserved;
    }

    public SshContext(Config config, AliasedConnection connection) {
        this.config = config;
        this.connection = connection;
        transportHandler = new ClientTcpTransportHandler(connection);
        chooser = new Chooser(this); // TODO this could introduce bugs
    }

    public SshContext() {

    }

    public Config getConfig() {
        return config;
    }

    public void setConfig(Config config) {
        this.config = config;
    }

    public AliasedConnection getConnection() {
        return connection;
    }

    public void setConnection(AliasedConnection connection) {
        this.connection = connection;
    }

    public byte[] getExchangeHash() {
        return exchangeHash;
    }

    public void setExchangeHash(byte[] exchangeHash) {
        this.exchangeHash = exchangeHash;
    }

    public byte[] getSessionID() {
        return sessionID;
    }

    public void setSessionID(byte[] sessionID) {
        this.sessionID = sessionID;
    }

    public byte[] getInitialIvClientToServer() {
        return initialIvClientToServer;
    }

    public void setInitialIvClientToServer(byte[] initialIvClientToServer) {
        this.initialIvClientToServer = initialIvClientToServer;
    }

    public byte[] getInitialIvServerToClient() {
        return initialIvServerToClient;
    }

    public void setInitialIvServerToClient(byte[] initialIvServerToClient) {
        this.initialIvServerToClient = initialIvServerToClient;
    }

    public byte[] getEncryptionKeyClientToServer() {
        return encryptionKeyClientToServer;
    }

    public void setEncryptionKeyClientToServer(byte[] encryptionKeyClientToServer) {
        this.encryptionKeyClientToServer = encryptionKeyClientToServer;
    }

    public byte[] getEncryptionKeyServerToClient() {
        return encryptionKeyServerToClient;
    }

    public void setEncryptionKeyServerToClient(byte[] encryptionKeyServerToClient) {
        this.encryptionKeyServerToClient = encryptionKeyServerToClient;
    }

    public byte[] getIntegrityKeyClientToServer() {
        return integrityKeyClientToServer;
    }

    public void setIntegrityKeyClientToServer(byte[] integrityKeyClientToServer) {
        this.integrityKeyClientToServer = integrityKeyClientToServer;
    }

    public byte[] getIntegrityKeyServerToClient() {
        return integrityKeyServerToClient;
    }

    public void setIntegrityKeyServerToClient(byte[] integrityKeyServerToClient) {
        this.integrityKeyServerToClient = integrityKeyServerToClient;
    }

    public String getHostKeyType() {
        return hostKeyType;
    }

    public void setHostKeyType(String hostKeyType) {
        this.hostKeyType = hostKeyType;
    }

    public byte[] getServerHostKey() {
        return serverHostKey;
    }

    public void setServerHostKey(byte[] serverHostKey) {
        this.serverHostKey = serverHostKey;
    }

    public byte[] getKeyExchangeSignature() {
        return keyExchangeSignature;
    }

    public void setKeyExchangeSignature(byte[] keyExchangeSignature) {
        this.keyExchangeSignature = keyExchangeSignature;
    }

    public Optional<KeyExchangeAlgorithm> getKeyExchangeAlgorithm() {
        return Optional.ofNullable(keyExchangeAlgorithm);
    }

    public void setKeyExchangeAlgorithm(KeyExchangeAlgorithm keyExchangeAlgorithm) {
        this.keyExchangeAlgorithm = keyExchangeAlgorithm;
    }

    public EncryptionAlgorithm getCipherAlgorithmClientToServer() {
        return cipherAlgorithmClientToServer;
    }

    public void setCipherAlgorithmClientToServer(EncryptionAlgorithm cipherAlgorithmClientToServer) {
        this.cipherAlgorithmClientToServer = cipherAlgorithmClientToServer;
    }

    public EncryptionAlgorithm getCipherAlgorithmServerToClient() {
        return cipherAlgorithmServerToClient;
    }

    public void setCipherAlgorithmServerToClient(EncryptionAlgorithm cipherAlgorithmServerToClient) {
        this.cipherAlgorithmServerToClient = cipherAlgorithmServerToClient;
    }

    public MacAlgorithm getMacAlgorithmClientToServer() {
        return macAlgorithmClientToServer;
    }

    public void setMacAlgorithmClientToServer(MacAlgorithm macAlgorithmClientToServer) {
        this.macAlgorithmClientToServer = macAlgorithmClientToServer;
    }

    public MacAlgorithm getMacAlgorithmServerToClient() {
        return macAlgorithmServerToClient;
    }

    public void setMacAlgorithmServerToClient(MacAlgorithm macAlgorithmServerToClient) {
        this.macAlgorithmServerToClient = macAlgorithmServerToClient;
    }

    public CompressionAlgorithm getCompressionAlgorithmClientToServer() {
        return compressionAlgorithmClientToServer;
    }

    public void setCompressionAlgorithmClientToServer(CompressionAlgorithm compressionAlgorithmClientToServer) {
        this.compressionAlgorithmClientToServer = compressionAlgorithmClientToServer;
    }

    public CompressionAlgorithm getCompressionAlgorithmServerToClient() {
        return compressionAlgorithmServerToClient;
    }

    public void setCompressionAlgorithmServerToClient(CompressionAlgorithm compressionAlgorithmServerToClient) {
        this.compressionAlgorithmServerToClient = compressionAlgorithmServerToClient;
    }

    public Language getLanguageClientToServer() {
        return languageClientToServer;
    }

    public void setLanguageClientToServer(Language languageClientToServer) {
        this.languageClientToServer = languageClientToServer;
    }

    public Language getLanguageServerToClient() {
        return languageServerToClient;
    }

    public void setLanguageServerToClient(Language languageServerToClient) {
        this.languageServerToClient = languageServerToClient;
    }

    public PublicKeyAuthenticationAlgorithm getServerHostKeyAlgorithm() {
        return serverHostKeyAlgorithm;
    }

    public void setServerHostKeyAlgorithm(PublicKeyAuthenticationAlgorithm serverHostKeyAlgorithm) {
        this.serverHostKeyAlgorithm = serverHostKeyAlgorithm;
    }

    public BigInteger getHostKeyRsaExponent() {
        return hostKeyRsaExponent;
    }

    public void setHostKeyRsaExponent(BigInteger hostKeyRsaExponent) {
        this.hostKeyRsaExponent = hostKeyRsaExponent;
    }

    public BigInteger getHostKeyRsaModulus() {
        return hostKeyRsaModulus;
    }

    public void setHostKeyRsaModulus(BigInteger hostKeyRsaModulus) {
        this.hostKeyRsaModulus = hostKeyRsaModulus;
    }

    public Chooser getChooser() {
        return chooser;
    }

    public void setChooser(Chooser chooser) {
        this.chooser = chooser;
    }

    public byte[] getExchangeHashInput() {
        return exchangeHashInput;
    }

    public void setExchangeHashInput(byte[] exchangeHashInput) {
        this.exchangeHashInput = exchangeHashInput;
    }

    public void appendToExchangeHashInput(byte[] additionalData) {
        exchangeHashInput = ArrayConverter.concatenate(exchangeHashInput,
                Converter.bytesToLengthPrefixedBinaryString(additionalData));
    }

    public KeyExchange getKeyExchangeInstance() {
        return keyExchangeInstance;
    }

    public void setKeyExchangeInstance(KeyExchange keyExchangeInstance) {
        this.keyExchangeInstance = keyExchangeInstance;
    }

    public BinaryPacketLayer getBinaryPacketLayer() {
        return binaryPacketLayer;
    }

    public MessageLayer getMessageLayer() {
        return messageLayer;
    }

    public TransportHandler getTransportHandler() {
        return transportHandler;
    }

    public void setBinaryPacketLayer(BinaryPacketLayer binaryPacketLayer) {
        this.binaryPacketLayer = binaryPacketLayer;
    }

    public void setMessageLayer(MessageLayer messageLayer) {
        this.messageLayer = messageLayer;
    }

    public void setTransportHandler(TransportHandler transportHandler) {
        this.transportHandler = transportHandler;
    }

    public int getSequenceNumber() {
        return sequenceNumber;
    }

    public void setSequenceNumber(int sequenceNumber) {
        this.sequenceNumber = sequenceNumber;
    }

    public void incrementSequenceNumter(int i) {
        sequenceNumber += i;
    }

    public void incrementSequenceNumber() {
        incrementSequenceNumter(1);
    }

    public boolean isEncryptionActive() {
        return isEncryptionActive;
    }

    public void setIsEncryptionActive(boolean isEncryptionActive) {
        this.isEncryptionActive = isEncryptionActive;
    }

    public boolean isKeyExchangeComplete() {
        return keyExchangeCompleted;
    }

    public void setKeyExchangeComplete(boolean keyExchangeCompleted) {
        this.keyExchangeCompleted = keyExchangeCompleted;
    }

    public CryptoLayer getCryptoLayerClientToServer() {
        return cryptoLayerClientToServer;
    }

    public void setCryptoLayerClientToServer(CryptoLayer cryptoLayerClientToServer) {
        this.cryptoLayerClientToServer = cryptoLayerClientToServer;
    }

    public CryptoLayer getCryptoLayerServerToClient() {
        return cryptoLayerServerToClient;
    }

    public void setCryptoLayerServerToClient(CryptoLayer cryptoLayerServerToClient) {
        this.cryptoLayerServerToClient = cryptoLayerServerToClient;
    }

    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }

    public int getLocalChannel() {
        return localChannel;
    }

    public void setLocalChannel(int localChannel) {
        this.localChannel = localChannel;
    }

    public int getWindowSize() {
        return windowSize;
    }

    public void setWindowSize(int windowSize) {
        this.windowSize = windowSize;
    }

    public int getPacketSize() {
        return packetSize;
    }

    public void setPacketSize(int packetSize) {
        this.packetSize = packetSize;
    }

    public ChannelType getChannelType() {
        return channelType;
    }

    public void setChannelType(ChannelType channelType) {
        this.channelType = channelType;
    }

    public String getChannelCommand() {
        return channelCommand;
    }

    public void setChannelCommand(String channelCommand) {
        this.channelCommand = channelCommand;
    }

    public byte getReplyWanted() {
        return replyWanted;
    }

    public void setReplyWanted(byte replyWanted) {
        this.replyWanted = replyWanted;
    }

    public ChannelRequestType getChannelRequestType() {
        return channelRequestType;
    }

    public void setChannelRequestType(ChannelRequestType channelRequestType) {
        this.channelRequestType = channelRequestType;
    }

    public int getRemoteChannel() {
        return remoteChannel;
    }

    public void setRemoteChannel(int remoteChannel) {
        this.remoteChannel = remoteChannel;
    }

    public boolean isReceivedTransportHandlerException() {
        return receivedTransportHandlerException;
    }

    public void setReceivedTransportHandlerException(boolean receivedTransportHandlerException) {
        this.receivedTransportHandlerException = receivedTransportHandlerException;
    }

    public Boolean getReceivedDisconnectMessage() {
        return receivedDisconnectMessage;
    }

    public void setReceivedDisconnectMessage(Boolean receivedDisconnectMessage) {
        this.receivedDisconnectMessage = receivedDisconnectMessage;
    }

    public void initTransportHandler() throws IOException {
        transportHandler.initialize();
    }

    public Boolean isVersionExchangeComplete() {
        return versionExchangeCompleted;
    }

    public void setVersionExchangeComplete(Boolean complete) {
        this.versionExchangeCompleted = complete;
    }

    public Optional<String> getServiceName() {
        return Optional.ofNullable(serviceName);
    }

    public void setServiceName(String serviceName) {
        this.serviceName = serviceName;
    }

    public Optional<AuthenticationMethod> getAuthenticationMethod() {
        return Optional.ofNullable(authenticationMethod);
    }

    public void setAuthenticationMethod(AuthenticationMethod authenticationMethod) {
        this.authenticationMethod = authenticationMethod;
    }
}
