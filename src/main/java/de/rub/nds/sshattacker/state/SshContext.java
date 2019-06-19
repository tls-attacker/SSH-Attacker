package de.rub.nds.sshattacker.state;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.sshattacker.config.Config;
import de.rub.nds.sshattacker.connection.AliasedConnection;
import de.rub.nds.sshattacker.constants.EncryptionAlgorithm;
import de.rub.nds.sshattacker.constants.CompressionAlgorithm;
import de.rub.nds.sshattacker.constants.KeyExchangeAlgorithm;
import de.rub.nds.sshattacker.constants.Language;
import de.rub.nds.sshattacker.constants.MacAlgorithm;
import de.rub.nds.sshattacker.constants.PublicKeyAuthenticationAlgorithm;
import de.rub.nds.sshattacker.protocol.layers.BinaryPacketLayer;
import de.rub.nds.sshattacker.protocol.layers.CryptoLayer;
import de.rub.nds.sshattacker.protocol.layers.MessageLayer;
import de.rub.nds.sshattacker.util.Converter;
import de.rub.nds.tlsattacker.transport.TransportHandler;
import java.math.BigInteger;
import java.util.List;

public class SshContext {

    private Config config;
    private Chooser chooser;
    private AliasedConnection connection;

    private BinaryPacketLayer binaryPacketLayer;
    private MessageLayer messageLayer;
    private TransportHandler transportHandler;
    private CryptoLayer cryptoLayer;

    private byte[] exchangeHashInput;

    private byte[] sharedSecret;
    private byte[] exchangeHash;
    private byte[] sessionID;

    private byte[] initialIvClientToServer;
    private byte[] initialIvServerToClient;

    private byte[] encryptionKeyClientToServer;
    private byte[] encryptionKeyServerToClient;

    private byte[] integrityKeyClientToServer;
    private byte[] integrityKeyServerToClient;

    private int sequenceNumber = 0;
    private boolean isEncryptionActive = false;
    
    private String hostKeyType;
    private byte[] serverHostKey;
    private BigInteger hostKeyRsaExponent;
    private BigInteger hostKeyRsaModulus;
    private byte[] keyExchangeSignature;

    private byte[] clientEcdhPublicKey;
    private byte[] clientEcdhSecretKey;
    private byte[] serverEcdhPublicKey;

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

// BEGIN_GENERATED
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

    public String getClientVersion() {
        return clientVersion;
    }

    public String getClientComment() {
        return clientComment;
    }

    public String getServerVersion() {
        return serverVersion;
    }

    public String getServerComment() {
        return serverComment;
    }

    public byte[] getClientCookie() {
        return clientCookie;
    }

    public byte[] getServerCookie() {
        return serverCookie;
    }

    public List<KeyExchangeAlgorithm> getClientSupportedKeyExchangeAlgorithms() {
        return clientSupportedKeyExchangeAlgorithms;
    }

    public List<KeyExchangeAlgorithm> getServerSupportedKeyExchangeAlgorithms() {
        return serverSupportedKeyExchangeAlgorithms;
    }

    public List<PublicKeyAuthenticationAlgorithm> getClientSupportedHostKeyAlgorithms() {
        return clientSupportedHostKeyAlgorithms;
    }

    public List<PublicKeyAuthenticationAlgorithm> getServerSupportedHostKeyAlgorithms() {
        return serverSupportedHostKeyAlgorithms;
    }

    public List<EncryptionAlgorithm> getClientSupportedCipherAlgorithmsClientToServer() {
        return clientSupportedCipherAlgorithmsClientToServer;
    }

    public List<EncryptionAlgorithm> getClientSupportedCipherAlgorithmsServerToClient() {
        return clientSupportedCipherAlgorithmsServerToClient;
    }

    public List<EncryptionAlgorithm> getServerSupportedCipherAlgorithmsServerToClient() {
        return serverSupportedCipherAlgorithmsServerToClient;
    }

    public List<EncryptionAlgorithm> getServerSupportedCipherAlgorithmsClientToServer() {
        return serverSupportedCipherAlgorithmsClientToServer;
    }

    public List<MacAlgorithm> getClientSupportedMacAlgorithmsClientToServer() {
        return clientSupportedMacAlgorithmsClientToServer;
    }

    public List<MacAlgorithm> getClientSupportedMacAlgorithmsServerToClient() {
        return clientSupportedMacAlgorithmsServerToClient;
    }

    public List<MacAlgorithm> getServerSupportedMacAlgorithmsServerToClient() {
        return serverSupportedMacAlgorithmsServerToClient;
    }

    public List<MacAlgorithm> getServerSupportedMacAlgorithmsClientToServer() {
        return serverSupportedMacAlgorithmsClientToServer;
    }

    public List<CompressionAlgorithm> getClientSupportedCompressionAlgorithmsClientToServer() {
        return clientSupportedCompressionAlgorithmsClientToServer;
    }

    public List<CompressionAlgorithm> getClientSupportedCompressionAlgorithmsServerToClient() {
        return clientSupportedCompressionAlgorithmsServerToClient;
    }

    public List<CompressionAlgorithm> getServerSupportedCompressionAlgorithmsServerToClient() {
        return serverSupportedCompressionAlgorithmsServerToClient;
    }

    public List<CompressionAlgorithm> getServerSupportedCompressionAlgorithmsClientToServer() {
        return serverSupportedCompressionAlgorithmsClientToServer;
    }

    public List<Language> getClientSupportedLanguagesClientToServer() {
        return clientSupportedLanguagesClientToServer;
    }

    public List<Language> getClientSupportedLanguagesServerToClient() {
        return clientSupportedLanguagesServerToClient;
    }

    public List<Language> getServerSupportedLanguagesServerToClient() {
        return serverSupportedLanguagesServerToClient;
    }

    public List<Language> getServerSupportedLanguagesClientToServer() {
        return serverSupportedLanguagesClientToServer;
    }

    public Byte getClientFirstKeyExchangePacketFollows() {
        return clientFirstKeyExchangePacketFollows;
    }

    public Byte getServerFirstKeyExchangePacketFollows() {
        return serverFirstKeyExchangePacketFollows;
    }

    public Integer getClientReserved() {
        return clientReserved;
    }

    public Integer getServerReserved() {
        return serverReserved;
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

    public void setClientSupportedHostKeyAlgorithms(List<PublicKeyAuthenticationAlgorithm> clientSupportedHostKeyAlgorithms) {
        this.clientSupportedHostKeyAlgorithms = clientSupportedHostKeyAlgorithms;
    }

    public void setServerSupportedHostKeyAlgorithms(List<PublicKeyAuthenticationAlgorithm> serverSupportedHostKeyAlgorithms) {
        this.serverSupportedHostKeyAlgorithms = serverSupportedHostKeyAlgorithms;
    }

    public void setClientSupportedCipherAlgorithmsClientToServer(List<EncryptionAlgorithm> clientSupportedCipherAlgorithmsClientToServer) {
        this.clientSupportedCipherAlgorithmsClientToServer = clientSupportedCipherAlgorithmsClientToServer;
    }

    public void setClientSupportedCipherAlgorithmsServerToClient(List<EncryptionAlgorithm> clientSupportedCipherAlgorithmsServerToClient) {
        this.clientSupportedCipherAlgorithmsServerToClient = clientSupportedCipherAlgorithmsServerToClient;
    }

    public void setServerSupportedCipherAlgorithmsServerToClient(List<EncryptionAlgorithm> serverSupportedCipherAlgorithmsServerToClient) {
        this.serverSupportedCipherAlgorithmsServerToClient = serverSupportedCipherAlgorithmsServerToClient;
    }

    public void setServerSupportedCipherAlgorithmsClientToServer(List<EncryptionAlgorithm> serverSupportedCipherAlgorithmsClientToServer) {
        this.serverSupportedCipherAlgorithmsClientToServer = serverSupportedCipherAlgorithmsClientToServer;
    }

    public void setClientSupportedMacAlgorithmsClientToServer(List<MacAlgorithm> clientSupportedMacAlgorithmsClientToServer) {
        this.clientSupportedMacAlgorithmsClientToServer = clientSupportedMacAlgorithmsClientToServer;
    }

    public void setClientSupportedMacAlgorithmsServerToClient(List<MacAlgorithm> clientSupportedMacAlgorithmsServerToClient) {
        this.clientSupportedMacAlgorithmsServerToClient = clientSupportedMacAlgorithmsServerToClient;
    }

    public void setServerSupportedMacAlgorithmsServerToClient(List<MacAlgorithm> serverSupportedMacAlgorithmsServerToClient) {
        this.serverSupportedMacAlgorithmsServerToClient = serverSupportedMacAlgorithmsServerToClient;
    }

    public void setServerSupportedMacAlgorithmsClientToServer(List<MacAlgorithm> serverSupportedMacAlgorithmsClientToServer) {
        this.serverSupportedMacAlgorithmsClientToServer = serverSupportedMacAlgorithmsClientToServer;
    }

    public void setClientSupportedCompressionAlgorithmsClientToServer(List<CompressionAlgorithm> clientSupportedCompressionAlgorithmsClientToServer) {
        this.clientSupportedCompressionAlgorithmsClientToServer = clientSupportedCompressionAlgorithmsClientToServer;
    }

    public void setClientSupportedCompressionAlgorithmsServerToClient(List<CompressionAlgorithm> clientSupportedCompressionAlgorithmsServerToClient) {
        this.clientSupportedCompressionAlgorithmsServerToClient = clientSupportedCompressionAlgorithmsServerToClient;
    }

    public void setServerSupportedCompressionAlgorithmsServerToClient(List<CompressionAlgorithm> serverSupportedCompressionAlgorithmsServerToClient) {
        this.serverSupportedCompressionAlgorithmsServerToClient = serverSupportedCompressionAlgorithmsServerToClient;
    }

    public void setServerSupportedCompressionAlgorithmsClientToServer(List<CompressionAlgorithm> serverSupportedCompressionAlgorithmsClientToServer) {
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

// END_GENERATED
    public SshContext(Config config, AliasedConnection connection) {
        this.config = config;
        this.connection = connection;
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

    public byte[] getSharedSecret() {
        return sharedSecret;
    }

    public void setSharedSecret(byte[] sharedSecret) {
        this.sharedSecret = sharedSecret;
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

    public KeyExchangeAlgorithm getKeyExchangeAlgorithm() {
        return keyExchangeAlgorithm;
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

    public byte[] getClientEcdhPublicKey() {
        return clientEcdhPublicKey;
    }

    public void setClientEcdhPublicKey(byte[] clientEcdhPublicKey) {
        this.clientEcdhPublicKey = clientEcdhPublicKey;
    }

    public byte[] getServerEcdhPublicKey() {
        return serverEcdhPublicKey;
    }

    public void setServerEcdhPublicKey(byte[] serverEcdhPublicKey) {
        this.serverEcdhPublicKey = serverEcdhPublicKey;
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
        exchangeHashInput = ArrayConverter.concatenate(exchangeHashInput, Converter.bytesToLenghPrefixedString(additionalData));
    }

    public byte[] getClientEcdhSecretKey() {
        return clientEcdhSecretKey;
    }

    public void setClientEcdhSecretKey(byte[] clientEcdhSecretKey) {
        this.clientEcdhSecretKey = clientEcdhSecretKey;
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
    
    public void incrementSequenceNumter(int i){
        sequenceNumber+=i;
    }
    
    public void incrementSequenceNumber(){
        incrementSequenceNumter(1);
    }

    public boolean isIsEncryptionActive() {
        return isEncryptionActive;
    }

    public void setIsEncryptionActive(boolean isEncryptionActive) {
        this.isEncryptionActive = isEncryptionActive;
    }

    public CryptoLayer getCryptoLayer() {
        return cryptoLayer;
    }

    public void setCryptoLayer(CryptoLayer cryptoLayer) {
        this.cryptoLayer = cryptoLayer;
    }
    
}
