package de.rub.nds.sshattacker.state;

import de.rub.nds.sshattacker.config.Config;
import de.rub.nds.sshattacker.connection.AliasedConnection;
import de.rub.nds.sshattacker.constants.EncryptionAlgorithm;
import de.rub.nds.sshattacker.constants.CompressionAlgorithm;
import de.rub.nds.sshattacker.constants.KeyExchangeAlgorithm;
import de.rub.nds.sshattacker.constants.Language;
import de.rub.nds.sshattacker.constants.MACAlgorithm;
import de.rub.nds.sshattacker.constants.PublicKeyAuthenticationAlgorithm;
import java.math.BigInteger;
import java.util.List;

public class SshContext {

    private Config config;
    private AliasedConnection connection;

    private byte[] sharedSecret;
    private byte[] exchangeHash;
    private byte[] sessionID;

    private byte[] initialIvClientToServer;
    private byte[] initialIvServerToClient;

    private byte[] encryptionKeyClientToServer;
    private byte[] encryptionKeyServerToClient;

    private byte[] integrityKeyClientToServer;
    private byte[] integrityKeyServerToClient;

    private byte[] defaultClientEcdhPublicKey;

    private String defaultHostKeyType;
    private BigInteger defaultRsaExponent;
    private BigInteger defaultRsaModulus;
    private byte[] defaultServerEcdhPublicKey;
    private byte[] serverHostKey;
    private byte[] keyExchangeSignature;

    /**
     * selected values for this connection
     */
    private KeyExchangeAlgorithm keyExchangeAlgorithm;
    private PublicKeyAuthenticationAlgorithm publicKeyAuthenticationAlgorithm;
    private EncryptionAlgorithm cipherAlgorithm;
    private MACAlgorithm macAlgorithm;
    private CompressionAlgorithm compressionAlgorithm;
    private Language language;

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
    private List<EncryptionAlgorithm> clientSupportedCipherAlgorithmsSending;
    private List<EncryptionAlgorithm> clientSupportedCipherAlgorithmsReceiving;
    private List<EncryptionAlgorithm> serverSupportedCipherAlgorithmsSending;
    private List<EncryptionAlgorithm> serverSupportedCipherAlgorithmsReceiving;
    private List<MACAlgorithm> clientSupportedMacAlgorithmsSending;
    private List<MACAlgorithm> clientSupportedMacAlgorithmsReceiving;
    private List<MACAlgorithm> serverSupportedMacAlgorithmsSending;
    private List<MACAlgorithm> serverSupportedMacAlgorithmsReceiving;
    private List<CompressionAlgorithm> clientSupportedCompressionAlgorithmsSending;
    private List<CompressionAlgorithm> clientSupportedCompressionAlgorithmsReceiving;
    private List<CompressionAlgorithm> serverSupportedCompressionAlgorithmsSending;
    private List<CompressionAlgorithm> serverSupportedCompressionAlgorithmsReceiving;
    private List<Language> clientSupportedLanguagesSending;
    private List<Language> clientSupportedLanguagesReceiving;
    private List<Language> serverSupportedLanguagesSending;
    private List<Language> serverSupportedLanguagesReceiving;
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

    public List<EncryptionAlgorithm> getClientSupportedCipherAlgorithmsSending() {
        return clientSupportedCipherAlgorithmsSending;
    }

    public List<EncryptionAlgorithm> getClientSupportedCipherAlgorithmsReceiving() {
        return clientSupportedCipherAlgorithmsReceiving;
    }

    public List<EncryptionAlgorithm> getServerSupportedCipherAlgorithmsSending() {
        return serverSupportedCipherAlgorithmsSending;
    }

    public List<EncryptionAlgorithm> getServerSupportedCipherAlgorithmsReceiving() {
        return serverSupportedCipherAlgorithmsReceiving;
    }

    public List<MACAlgorithm> getClientSupportedMacAlgorithmsSending() {
        return clientSupportedMacAlgorithmsSending;
    }

    public List<MACAlgorithm> getClientSupportedMacAlgorithmsReceiving() {
        return clientSupportedMacAlgorithmsReceiving;
    }

    public List<MACAlgorithm> getServerSupportedMacAlgorithmsSending() {
        return serverSupportedMacAlgorithmsSending;
    }

    public List<MACAlgorithm> getServerSupportedMacAlgorithmsReceiving() {
        return serverSupportedMacAlgorithmsReceiving;
    }

    public List<CompressionAlgorithm> getClientSupportedCompressionAlgorithmsSending() {
        return clientSupportedCompressionAlgorithmsSending;
    }

    public List<CompressionAlgorithm> getClientSupportedCompressionAlgorithmsReceiving() {
        return clientSupportedCompressionAlgorithmsReceiving;
    }

    public List<CompressionAlgorithm> getServerSupportedCompressionAlgorithmsSending() {
        return serverSupportedCompressionAlgorithmsSending;
    }

    public List<CompressionAlgorithm> getServerSupportedCompressionAlgorithmsReceiving() {
        return serverSupportedCompressionAlgorithmsReceiving;
    }

    public List<Language> getClientSupportedLanguagesSending() {
        return clientSupportedLanguagesSending;
    }

    public List<Language> getClientSupportedLanguagesReceiving() {
        return clientSupportedLanguagesReceiving;
    }

    public List<Language> getServerSupportedLanguagesSending() {
        return serverSupportedLanguagesSending;
    }

    public List<Language> getServerSupportedLanguagesReceiving() {
        return serverSupportedLanguagesReceiving;
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

    public void setClientSupportedCipherAlgorithmsSending(List<EncryptionAlgorithm> clientSupportedCipherAlgorithmsSending) {
        this.clientSupportedCipherAlgorithmsSending = clientSupportedCipherAlgorithmsSending;
    }

    public void setClientSupportedCipherAlgorithmsReceiving(List<EncryptionAlgorithm> clientSupportedCipherAlgorithmsReceiving) {
        this.clientSupportedCipherAlgorithmsReceiving = clientSupportedCipherAlgorithmsReceiving;
    }

    public void setServerSupportedCipherAlgorithmsSending(List<EncryptionAlgorithm> serverSupportedCipherAlgorithmsSending) {
        this.serverSupportedCipherAlgorithmsSending = serverSupportedCipherAlgorithmsSending;
    }

    public void setServerSupportedCipherAlgorithmsReceiving(List<EncryptionAlgorithm> serverSupportedCipherAlgorithmsReceiving) {
        this.serverSupportedCipherAlgorithmsReceiving = serverSupportedCipherAlgorithmsReceiving;
    }

    public void setClientSupportedMacAlgorithmsSending(List<MACAlgorithm> clientSupportedMacAlgorithmsSending) {
        this.clientSupportedMacAlgorithmsSending = clientSupportedMacAlgorithmsSending;
    }

    public void setClientSupportedMacAlgorithmsReceiving(List<MACAlgorithm> clientSupportedMacAlgorithmsReceiving) {
        this.clientSupportedMacAlgorithmsReceiving = clientSupportedMacAlgorithmsReceiving;
    }

    public void setServerSupportedMacAlgorithmsSending(List<MACAlgorithm> serverSupportedMacAlgorithmsSending) {
        this.serverSupportedMacAlgorithmsSending = serverSupportedMacAlgorithmsSending;
    }

    public void setServerSupportedMacAlgorithmsReceiving(List<MACAlgorithm> serverSupportedMacAlgorithmsReceiving) {
        this.serverSupportedMacAlgorithmsReceiving = serverSupportedMacAlgorithmsReceiving;
    }

    public void setClientSupportedCompressionAlgorithmsSending(List<CompressionAlgorithm> clientSupportedCompressionAlgorithmsSending) {
        this.clientSupportedCompressionAlgorithmsSending = clientSupportedCompressionAlgorithmsSending;
    }

    public void setClientSupportedCompressionAlgorithmsReceiving(List<CompressionAlgorithm> clientSupportedCompressionAlgorithmsReceiving) {
        this.clientSupportedCompressionAlgorithmsReceiving = clientSupportedCompressionAlgorithmsReceiving;
    }

    public void setServerSupportedCompressionAlgorithmsSending(List<CompressionAlgorithm> serverSupportedCompressionAlgorithmsSending) {
        this.serverSupportedCompressionAlgorithmsSending = serverSupportedCompressionAlgorithmsSending;
    }

    public void setServerSupportedCompressionAlgorithmsReceiving(List<CompressionAlgorithm> serverSupportedCompressionAlgorithmsReceiving) {
        this.serverSupportedCompressionAlgorithmsReceiving = serverSupportedCompressionAlgorithmsReceiving;
    }

    public void setClientSupportedLanguagesSending(List<Language> clientSupportedLanguagesSending) {
        this.clientSupportedLanguagesSending = clientSupportedLanguagesSending;
    }

    public void setClientSupportedLanguagesReceiving(List<Language> clientSupportedLanguagesReceiving) {
        this.clientSupportedLanguagesReceiving = clientSupportedLanguagesReceiving;
    }

    public void setServerSupportedLanguagesSending(List<Language> serverSupportedLanguagesSending) {
        this.serverSupportedLanguagesSending = serverSupportedLanguagesSending;
    }

    public void setServerSupportedLanguagesReceiving(List<Language> serverSupportedLanguagesReceiving) {
        this.serverSupportedLanguagesReceiving = serverSupportedLanguagesReceiving;
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
}
