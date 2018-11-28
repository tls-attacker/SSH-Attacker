package de.rub.nds.sshattacker.state;

import de.rub.nds.sshattacker.config.Config;
import de.rub.nds.sshattacker.connection.AliasedConnection;
import de.rub.nds.sshattacker.constants.CipherAlgorithm;
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
    private List<CipherAlgorithm> clientSupportedCipherAlgorithms;
    private List<CipherAlgorithm> serverSupportedCipherAlgorithms;
    private List<MACAlgorithm> clientSupportedMacAlgorithms;
    private List<MACAlgorithm> serverSupportedMacAlgorithms;
    private List<CompressionAlgorithm> clientSupportedCompressionAlgorithms;
    private List<CompressionAlgorithm> serverSupportedCompressionAlgorithms;
    private List<Language> clientSupportedLanguages;
    private List<Language> serverSupportedLanguages;
    private byte firstKeyExchangePacketFollows;
    private int reserved;
    
    private byte[] defaultClientEcdhPublicKey;

    private String defaultHostKeyType;
    private BigInteger defaultRsaExponent;
    private BigInteger defaultRsaModulus;
    private byte[] defaultServerEcdhPublicKey;
    
    /**
     * selected values for this connection
     */
    private KeyExchangeAlgorithm keyExchangeAlgorithm;
    private PublicKeyAuthenticationAlgorithm publicKeyAuthenticationAlgorithm;
    private CipherAlgorithm cipherAlgorithm;
    private MACAlgorithm macAlgorithm;
    private CompressionAlgorithm compressionAlgorithm;
    private Language language;

    public SshContext(Config config, AliasedConnection connection) {
        this.config = config;
        this.connection = connection;
        initFromConfig();
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

    public List<KeyExchangeAlgorithm> getClientSupportedKeyExchangeAlgorithms() {
        return clientSupportedKeyExchangeAlgorithms;
    }

    public void setClientSupportedKeyExchangeAlgorithms(List<KeyExchangeAlgorithm> clientSupportedKeyExchangeAlgorithms) {
        this.clientSupportedKeyExchangeAlgorithms = clientSupportedKeyExchangeAlgorithms;
    }

    public List<KeyExchangeAlgorithm> getServerSupportedKeyExchangeAlgorithms() {
        return serverSupportedKeyExchangeAlgorithms;
    }

    public void setServerSupportedKeyExchangeAlgorithms(List<KeyExchangeAlgorithm> serverSupportedKeyExchangeAlgorithms) {
        this.serverSupportedKeyExchangeAlgorithms = serverSupportedKeyExchangeAlgorithms;
    }

    public List<PublicKeyAuthenticationAlgorithm> getClientSupportedHostKeyAlgorithms() {
        return clientSupportedHostKeyAlgorithms;
    }

    public void setClientSupportedHostKeyAlgorithms(List<PublicKeyAuthenticationAlgorithm> clientSupportedHostKeyAlgorithms) {
        this.clientSupportedHostKeyAlgorithms = clientSupportedHostKeyAlgorithms;
    }

    public List<PublicKeyAuthenticationAlgorithm> getServerSupportedHostKeyAlgorithms() {
        return serverSupportedHostKeyAlgorithms;
    }

    public void setServerSupportedHostKeyAlgorithms(List<PublicKeyAuthenticationAlgorithm> serverSupportedHostKeyAlgorithms) {
        this.serverSupportedHostKeyAlgorithms = serverSupportedHostKeyAlgorithms;
    }

    public List<CipherAlgorithm> getClientSupportedCipherAlgorithms() {
        return clientSupportedCipherAlgorithms;
    }

    public void setClientSupportedCipherAlgorithms(List<CipherAlgorithm> clientSupportedCipherAlgorithms) {
        this.clientSupportedCipherAlgorithms = clientSupportedCipherAlgorithms;
    }

    public List<CipherAlgorithm> getServerSupportedCipherAlgorithms() {
        return serverSupportedCipherAlgorithms;
    }

    public void setServerSupportedCipherAlgorithms(List<CipherAlgorithm> serverSupportedCipherAlgorithms) {
        this.serverSupportedCipherAlgorithms = serverSupportedCipherAlgorithms;
    }

    public List<MACAlgorithm> getClientSupportedMacAlgorithms() {
        return clientSupportedMacAlgorithms;
    }

    public void setClientSupportedMacAlgorithms(List<MACAlgorithm> clientSupportedMacAlgorithms) {
        this.clientSupportedMacAlgorithms = clientSupportedMacAlgorithms;
    }

    public List<MACAlgorithm> getServerSupportedMacAlgorithms() {
        return serverSupportedMacAlgorithms;
    }

    public void setServerSupportedMacAlgorithms(List<MACAlgorithm> serverSupportedMacAlgorithms) {
        this.serverSupportedMacAlgorithms = serverSupportedMacAlgorithms;
    }

    public List<CompressionAlgorithm> getClientSupportedCompressionAlgorithms() {
        return clientSupportedCompressionAlgorithms;
    }

    public void setClientSupportedCompressionAlgorithms(List<CompressionAlgorithm> clientSupportedCompressionAlgorithms) {
        this.clientSupportedCompressionAlgorithms = clientSupportedCompressionAlgorithms;
    }

    public List<CompressionAlgorithm> getServerSupportedCompressionAlgorithms() {
        return serverSupportedCompressionAlgorithms;
    }

    public void setServerSupportedCompressionAlgorithms(List<CompressionAlgorithm> serverSupportedCompressionAlgorithms) {
        this.serverSupportedCompressionAlgorithms = serverSupportedCompressionAlgorithms;
    }

    public List<Language> getClientSupportedLanguages() {
        return clientSupportedLanguages;
    }

    public void setClientSupportedLanguages(List<Language> clientSupportedLanguages) {
        this.clientSupportedLanguages = clientSupportedLanguages;
    }

    public List<Language> getServerSupportedLanguages() {
        return serverSupportedLanguages;
    }

    public void setServerSupportedLanguages(List<Language> serverSupportedLanguages) {
        this.serverSupportedLanguages = serverSupportedLanguages;
    }

    public KeyExchangeAlgorithm getKeyExchangeAlgorithm() {
        return keyExchangeAlgorithm;
    }

    public void setKeyExchangeAlgorithm(KeyExchangeAlgorithm keyExchangeAlgorithm) {
        this.keyExchangeAlgorithm = keyExchangeAlgorithm;
    }

    public PublicKeyAuthenticationAlgorithm getPublicKeyAuthenticationAlgorithm() {
        return publicKeyAuthenticationAlgorithm;
    }

    public void setPublicKeyAuthenticationAlgorithm(PublicKeyAuthenticationAlgorithm publicKeyAuthenticationAlgorithm) {
        this.publicKeyAuthenticationAlgorithm = publicKeyAuthenticationAlgorithm;
    }

    public CipherAlgorithm getCipherAlgorithm() {
        return cipherAlgorithm;
    }

    public void setCipherAlgorithm(CipherAlgorithm cipherAlgorithm) {
        this.cipherAlgorithm = cipherAlgorithm;
    }

    public MACAlgorithm getMacAlgorithm() {
        return macAlgorithm;
    }

    public void setMacAlgorithm(MACAlgorithm macAlgorithm) {
        this.macAlgorithm = macAlgorithm;
    }

    public CompressionAlgorithm getCompressionAlgorithm() {
        return compressionAlgorithm;
    }

    public void setCompressionAlgorithm(CompressionAlgorithm compressionAlgorithm) {
        this.compressionAlgorithm = compressionAlgorithm;
    }

    public Language getLanguage() {
        return language;
    }

    public void setLanguage(Language language) {
        this.language = language;
    }

    public byte[] getClientCookie() {
        return clientCookie;
    }

    public void setClientCookie(byte[] clientCookie) {
        this.clientCookie = clientCookie;
    }

    public byte[] getServerCookie() {
        return serverCookie;
    }

    public void setServerCookie(byte[] serverCookie) {
        this.serverCookie = serverCookie;
    }

    public String getClientVersion() {
        return clientVersion;
    }

    public void setClientVersion(String clientVersion) {
        this.clientVersion = clientVersion;
    }

    public String getServerVersion() {
        return serverVersion;
    }

    public void setServerVersion(String serverVersion) {
        this.serverVersion = serverVersion;
    }

    public String getClientComment() {
        return clientComment;
    }

    public void setClientComment(String clientComment) {
        this.clientComment = clientComment;
    }

    public String getServerComment() {
        return serverComment;
    }

    public void setServerComment(String serverComment) {
        this.serverComment = serverComment;
    }

    public byte[] getDefaultClientEcdhPublicKey() {
        return defaultClientEcdhPublicKey;
    }

    public void setDefaultClientEcdhPublicKey(byte[] defaultClientEcdhPublicKey) {
        this.defaultClientEcdhPublicKey = defaultClientEcdhPublicKey;
    }

    public String getDefaultHostKeyType() {
        return defaultHostKeyType;
    }

    public void setDefaultHostKeyType(String defaultHostKeyType) {
        this.defaultHostKeyType = defaultHostKeyType;
    }

    public BigInteger getDefaultRsaExponent() {
        return defaultRsaExponent;
    }

    public void setDefaultRsaExponent(BigInteger defaultRsaExponent) {
        this.defaultRsaExponent = defaultRsaExponent;
    }

    public BigInteger getDefaultRsaModulus() {
        return defaultRsaModulus;
    }

    public void setDefaultRsaModulus(BigInteger defaultRsaModulus) {
        this.defaultRsaModulus = defaultRsaModulus;
    }

    public byte[] getDefaultServerEcdhPublicKey() {
        return defaultServerEcdhPublicKey;
    }

    public void setDefaultServerEcdhPublicKey(byte[] defaultServerEcdhPublicKey) {
        this.defaultServerEcdhPublicKey = defaultServerEcdhPublicKey;
    }

    public byte getFirstKeyExchangePacketFollows() {
        return firstKeyExchangePacketFollows;
    }

    public void setFirstKeyExchangePacketFollows(byte firstKeyExchangePacketFollows) {
        this.firstKeyExchangePacketFollows = firstKeyExchangePacketFollows;
    }

    public int getReserved() {
        return reserved;
    }

    public void setReserved(int reserved) {
        this.reserved = reserved;
    }
    
    
    private void initFromConfig(){
        this.clientVersion = config.getClientVersion();
        this.clientComment = config.getClientComment();
        this.serverVersion = config.getServerVersion();
        this.serverComment = config.getServerComment();
        this.clientCookie = config.getClientCookie();
        this.serverCookie = config.getServerCookie();
        this.defaultClientEcdhPublicKey = config.getDefaultClientEcdhPublicKey();
        this.defaultServerEcdhPublicKey = config.getDefaultServerEcdhPublicKey();
        this.defaultRsaExponent = config.getDefaultRsaExponent();
        this.defaultRsaModulus = config.getDefaultRsaModulus();
        this.clientSupportedKeyExchangeAlgorithms = config.getSupportedKeyExchangeAlgorithms();
        this.serverSupportedKeyExchangeAlgorithms = config.getSupportedKeyExchangeAlgorithms();
        this.clientSupportedHostKeyAlgorithms = config.getPublicKeyAuthenticationAlgorithms();
        this.serverSupportedHostKeyAlgorithms = config.getPublicKeyAuthenticationAlgorithms();
        this.clientSupportedCipherAlgorithms = config.getSupportedEncryptionAlgorithmsClientToServer();
        this.serverSupportedCipherAlgorithms = config.getSupportedEncryptionAlgorithmsServerToClient();
        this.clientSupportedMacAlgorithms = config.getSupportedMacAlgorithmsClientToServer();
        this.serverSupportedMacAlgorithms = config.getSupportedMacAlgorithmsServerToClient();
        this.clientSupportedCompressionAlgorithms = config.getSupportedCompressionAlgorithmsClientToServer();
        this.serverSupportedCompressionAlgorithms = config.getSupportedCompressionAlgorithmsServerToClient();
        this.clientSupportedLanguages = config.getSupportedLanguagesClientToServer();
        this.serverSupportedLanguages = config.getSupportedLanguagesServerToClient();
    }
}
