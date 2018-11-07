package de.rub.nds.sshattacker.config;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.sshattacker.connection.InboundConnection;
import de.rub.nds.sshattacker.connection.OutboundConnection;
import de.rub.nds.sshattacker.constants.CipherAlgorithm;
import de.rub.nds.sshattacker.constants.CompressionAlgorithm;
import de.rub.nds.sshattacker.constants.KeyExchangeAlgorithm;
import de.rub.nds.sshattacker.constants.Language;
import de.rub.nds.sshattacker.constants.MACAlgorithm;
import de.rub.nds.sshattacker.constants.PublicKeyAuthenticationAlgorithm;
import de.rub.nds.sshattacker.constants.RunningModeType;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.Serializable;
import java.lang.reflect.Field;
import java.math.BigInteger;
import java.util.LinkedList;
import java.util.List;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class Config implements Serializable {

    private static final Logger LOGGER = LogManager.getLogger();

    private static final String DEFAULT_CONFIG_FILE = "/default_config.xml";

    private static final ConfigCache DEFAULT_CONFIG_CACHE;

    static {
        DEFAULT_CONFIG_CACHE = new ConfigCache(createConfig());
    }

    /**
     * From ClientInitMessage
     */
    private String version;
    private String comment;

    /**
     * From KeyExchangeInitMessage
     */
    private byte[] cookie;
    private List<KeyExchangeAlgorithm> supportedKeyExchangeAlgorithms;
    private List<PublicKeyAuthenticationAlgorithm> supportedHostKeyAlgorithms;
    private List<CipherAlgorithm> supportedEncryptionAlgorithmsClientToServer;
    private List<CipherAlgorithm> supportedEncryptionAlgorithmsServerToClient;
    private List<MACAlgorithm> supportedMacAlgorithmsClientToServer;
    private List<MACAlgorithm> supportedMacAlgorithmsServerToClient;
    private List<CompressionAlgorithm> supportedCompressionAlgorithmsClientToServer;
    private List<CompressionAlgorithm> supportedCompressionAlgorithmsServerToClient;
    private List<Language> supportedLanguagesClientToServer;
    private List<Language> supportedLanguagesServerToClient;
    private byte defaultFirstKeyExchangePacketFollows;
    private int defaultReserved;

    /**
     * From ECDHKeyExchangeInitMessage
     */
    private byte[] defaultClientEcdhPublicKey;

    /**
     * From ECDHKeyExchangeReplyMessage
     */
    private String defaultHostKeyType;
    private BigInteger defaultRsaExponent;
    private BigInteger defaultRsaModulus;
    private byte[] defaultServerEcdhPublicKey;

    /**
     * Default Connection to use when running as Client
     */
    private OutboundConnection defaultClientConnection;

    /**
     * Default Connection to use when running as Server
     */
    private InboundConnection defaultServerConnection;

    private RunningModeType defaultRunningMode = RunningModeType.CLIENT;

    Config() {
        defaultClientConnection = new OutboundConnection("client", 443, "localhost");
        defaultServerConnection = new InboundConnection("server", 443);
        version = "SSH-2.0-OpenSSH_7.8";
        comment = "";
        cookie = ArrayConverter.hexStringToByteArray("0000000000000000");
        supportedKeyExchangeAlgorithms = new LinkedList<>();
        supportedKeyExchangeAlgorithms.add(KeyExchangeAlgorithm.diffie_hellman_group1_sha1);
        supportedKeyExchangeAlgorithms.add(KeyExchangeAlgorithm.diffie_hellman_group14_sha1);
        supportedHostKeyAlgorithms = new LinkedList<>();
        supportedHostKeyAlgorithms.add(PublicKeyAuthenticationAlgorithm.ssh_dss);
        supportedEncryptionAlgorithmsClientToServer = new LinkedList<>();
        supportedEncryptionAlgorithmsClientToServer.add(CipherAlgorithm.tdes_cbc);
        supportedEncryptionAlgorithmsServerToClient = new LinkedList<>();
        supportedEncryptionAlgorithmsServerToClient.add(CipherAlgorithm.tdes_cbc);
        supportedMacAlgorithmsClientToServer = new LinkedList<>();
        supportedMacAlgorithmsClientToServer.add(MACAlgorithm.hmac_sha1);
        supportedMacAlgorithmsServerToClient = new LinkedList<>();
        supportedMacAlgorithmsServerToClient.add(MACAlgorithm.hmac_sha1);
        supportedCompressionAlgorithmsClientToServer = new LinkedList<>();
        supportedCompressionAlgorithmsClientToServer.add(CompressionAlgorithm.none);
        supportedCompressionAlgorithmsServerToClient = new LinkedList<>();
        supportedCompressionAlgorithmsServerToClient.add(CompressionAlgorithm.none);
        supportedLanguagesClientToServer = new LinkedList<>();
        supportedLanguagesClientToServer.add(Language.None);
        supportedLanguagesServerToClient = new LinkedList<>();
        supportedLanguagesServerToClient.add(Language.None);
        defaultFirstKeyExchangePacketFollows = (byte) 0;
        defaultReserved = 0;
    }

    public static Config createConfig() {
        if (DEFAULT_CONFIG_CACHE != null) {
            return DEFAULT_CONFIG_CACHE.getCachedCopy();
        }
        InputStream stream = Config.class.getResourceAsStream(DEFAULT_CONFIG_FILE);
        return ConfigIO.read(stream);
    }

    public static Config createConfig(File f) {
        return ConfigIO.read(f);
    }

    public static Config createConfig(InputStream stream) {
        Config config = ConfigIO.read(stream);
        try {
            stream.close();
        } catch (IOException ex) {
            LOGGER.warn("Could not close resource Stream!", ex);
            return ConfigIO.read(stream);
        }
        return config;
    }

    public static Config createEmptyConfig() {
        Config c = new Config();
        for (Field field : c.getClass().getDeclaredFields()) {
            if (!field.getName().equals("LOGGER") && !field.getType().isPrimitive()
                    && !field.getName().contains("Extension")) {
                field.setAccessible(true);
                try {
                    field.set(c, null);
                } catch (IllegalAccessException e) {
                    LOGGER.warn("Could not set field in Config!", e);
                }
            }
        }
        return c;
    }

    public String getVersion() {
        return version;
    }

    public void setVersion(String version) {
        this.version = version;
    }

    public String getComment() {
        return comment;
    }

    public void setComment(String comment) {
        this.comment = comment;
    }

    public byte[] getCookie() {
        return cookie;
    }

    public void setCookie(byte[] cookie) {
        this.cookie = cookie;
    }

    public List<KeyExchangeAlgorithm> getSupportedKeyExchangeAlgorithms() {
        return supportedKeyExchangeAlgorithms;
    }

    public void setSupportedKeyExchangeAlgorithms(List<KeyExchangeAlgorithm> supportedKeyExchangeAlgorithms) {
        this.supportedKeyExchangeAlgorithms = supportedKeyExchangeAlgorithms;
    }

    public List<PublicKeyAuthenticationAlgorithm> getSupportedHostKeyAlgorithms() {
        return supportedHostKeyAlgorithms;
    }

    public void setSupportedHostKeyAlgorithms(List<PublicKeyAuthenticationAlgorithm> supportedHostKeyAlgorithms) {
        this.supportedHostKeyAlgorithms = supportedHostKeyAlgorithms;
    }

    public List<CipherAlgorithm> getSupportedEncryptionAlgorithmsClientToServer() {
        return supportedEncryptionAlgorithmsClientToServer;
    }

    public void setSupportedEncryptionAlgorithmsClientToServer(List<CipherAlgorithm> supportedEncryptionAlgorithmsClientToServer) {
        this.supportedEncryptionAlgorithmsClientToServer = supportedEncryptionAlgorithmsClientToServer;
    }

    public List<CipherAlgorithm> getSupportedEncryptionAlgorithmsServerToClient() {
        return supportedEncryptionAlgorithmsServerToClient;
    }

    public void setSupportedEncryptionAlgorithmsServerToClient(List<CipherAlgorithm> supportedEncryptionAlgorithmsServerToClient) {
        this.supportedEncryptionAlgorithmsServerToClient = supportedEncryptionAlgorithmsServerToClient;
    }

    public List<MACAlgorithm> getSupportedMacAlgorithmsClientToServer() {
        return supportedMacAlgorithmsClientToServer;
    }

    public void setSupportedMacAlgorithmsClientToServer(List<MACAlgorithm> supportedMacAlgorithmsClientToServer) {
        this.supportedMacAlgorithmsClientToServer = supportedMacAlgorithmsClientToServer;
    }

    public List<MACAlgorithm> getSupportedMacAlgorithmsServerToClient() {
        return supportedMacAlgorithmsServerToClient;
    }

    public void setSupportedMacAlgorithmsServerToClient(List<MACAlgorithm> supportedMacAlgorithmsServerToClient) {
        this.supportedMacAlgorithmsServerToClient = supportedMacAlgorithmsServerToClient;
    }

    public List<CompressionAlgorithm> getSupportedCompressionAlgorithmsClientToServer() {
        return supportedCompressionAlgorithmsClientToServer;
    }

    public void setSupportedCompressionAlgorithmsClientToServer(List<CompressionAlgorithm> supportedCompressionAlgorithmsClientToServer) {
        this.supportedCompressionAlgorithmsClientToServer = supportedCompressionAlgorithmsClientToServer;
    }

    public List<CompressionAlgorithm> getSupportedCompressionAlgorithmsServerToClient() {
        return supportedCompressionAlgorithmsServerToClient;
    }

    public void setSupportedCompressionAlgorithmsServerToClient(List<CompressionAlgorithm> supportedCompressionAlgorithmsServerToClient) {
        this.supportedCompressionAlgorithmsServerToClient = supportedCompressionAlgorithmsServerToClient;
    }

    public List<Language> getSupportedLanguagesClientToServer() {
        return supportedLanguagesClientToServer;
    }

    public void setSupportedLanguagesClientToServer(List<Language> supportedLanguagesClientToServer) {
        this.supportedLanguagesClientToServer = supportedLanguagesClientToServer;
    }

    public List<Language> getSupportedLanguagesServerToClient() {
        return supportedLanguagesServerToClient;
    }

    public void setSupportedLanguagesServerToClient(List<Language> supportedLanguagesServerToClient) {
        this.supportedLanguagesServerToClient = supportedLanguagesServerToClient;
    }

    public byte getDefaultFirstKeyExchangePacketFollows() {
        return defaultFirstKeyExchangePacketFollows;
    }

    public void setDefaultFirstKeyExchangePacketFollows(byte defaultFirstKeyExchangePacketFollows) {
        this.defaultFirstKeyExchangePacketFollows = defaultFirstKeyExchangePacketFollows;
    }

    public int getDefaultReserved() {
        return defaultReserved;
    }

    public void setDefaultReserved(int defaultReserved) {
        this.defaultReserved = defaultReserved;
    }

    public OutboundConnection getDefaultClientConnection() {
        return defaultClientConnection;
    }

    public void setDefaultClientConnection(OutboundConnection defaultClientConnection) {
        this.defaultClientConnection = defaultClientConnection;
    }

    public InboundConnection getDefaultServerConnection() {
        return defaultServerConnection;
    }

    public void setDefaultServerConnection(InboundConnection defaultServerConnection) {
        this.defaultServerConnection = defaultServerConnection;
    }

    public RunningModeType getDefaultRunningMode() {
        return defaultRunningMode;
    }

    public void setDefaultRunningMode(RunningModeType defaultRunningMode) {
        this.defaultRunningMode = defaultRunningMode;
    }

}
