package de.rub.nds.sshattacker.config;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.sshattacker.connection.InboundConnection;
import de.rub.nds.sshattacker.connection.OutboundConnection;
import de.rub.nds.sshattacker.constants.EncryptionAlgorithm;
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
    private List<MACAlgorithm> clientSupportedMacAlgorithmsClientToServer;
    private List<MACAlgorithm> clientSupportedMacAlgorithmsServerToClient;
    private List<MACAlgorithm> serverSupportedMacAlgorithmsServerToClient;
    private List<MACAlgorithm> serverSupportedMacAlgorithmsClientToServer;
    private List<CompressionAlgorithm> clientSupportedCompressionAlgorithmsClientToServer;
    private List<CompressionAlgorithm> clientSupportedCompressionAlgorithmsServerToClient;
    private List<CompressionAlgorithm> serverSupportedCompressionAlgorithmsServerToClient;
    private List<CompressionAlgorithm> serverSupportedCompressionAlgorithmsClientToServer;
    private List<Language> clientSupportedLanguagesClientToServer;
    private List<Language> clientSupportedLanguagesServerToClient;
    private List<Language> serverSupportedLanguagesServerToClient;
    private List<Language> serverSupportedLanguagesClientToServer;
    private byte clientFirstKeyExchangePacketFollows;
    private byte serverFirstKeyExchangePacketFollows;
    private int clientReserved;
    private int serverReserved;
// END GENERATED
    
    private byte[] clientEcdhPublicKey;
    private byte[] serverEcdhPublicKey;
    
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
        defaultClientConnection = new OutboundConnection("client", 22, "localhost");
        defaultServerConnection = new InboundConnection("server", 22);
        clientVersion = "SSH-2.0-OpenSSH_7.8";
        clientComment = "";
        serverVersion = "SSH-2.0-libssh_0.7.0";
        serverComment = "";
        clientCookie = ArrayConverter.hexStringToByteArray("0000000000000000");

        clientSupportedKeyExchangeAlgorithms = new LinkedList<>();
        clientSupportedKeyExchangeAlgorithms.add(KeyExchangeAlgorithm.diffie_hellman_group1_sha1);
        clientSupportedKeyExchangeAlgorithms.add(KeyExchangeAlgorithm.diffie_hellman_group14_sha1);

        serverSupportedKeyExchangeAlgorithms = new LinkedList<>(clientSupportedKeyExchangeAlgorithms);

        clientSupportedHostKeyAlgorithms = new LinkedList<>();
        clientSupportedHostKeyAlgorithms.add(PublicKeyAuthenticationAlgorithm.ssh_dss);

        serverSupportedHostKeyAlgorithms = new LinkedList<>(clientSupportedHostKeyAlgorithms);

        clientSupportedCipherAlgorithmsClientToServer = new LinkedList<>();
        clientSupportedCipherAlgorithmsClientToServer.add(EncryptionAlgorithm.tdes_cbc);
        clientSupportedCipherAlgorithmsServerToClient = new LinkedList<>(clientSupportedCipherAlgorithmsClientToServer);

        serverSupportedCipherAlgorithmsClientToServer = new LinkedList<>(clientSupportedCipherAlgorithmsClientToServer);
        serverSupportedCipherAlgorithmsServerToClient = new LinkedList<>(clientSupportedCipherAlgorithmsClientToServer);

        clientSupportedMacAlgorithmsClientToServer = new LinkedList<>();
        clientSupportedMacAlgorithmsClientToServer.add(MACAlgorithm.hmac_sha1);
        clientSupportedMacAlgorithmsServerToClient = new LinkedList<>(clientSupportedMacAlgorithmsClientToServer);

        serverSupportedMacAlgorithmsServerToClient = new LinkedList<>(clientSupportedMacAlgorithmsClientToServer);
        serverSupportedMacAlgorithmsClientToServer = new LinkedList<>(clientSupportedMacAlgorithmsClientToServer);

        clientSupportedCompressionAlgorithmsClientToServer = new LinkedList<>();
        clientSupportedCompressionAlgorithmsClientToServer.add(CompressionAlgorithm.none);
        clientSupportedCompressionAlgorithmsServerToClient = new LinkedList<>(clientSupportedCompressionAlgorithmsClientToServer);

        serverSupportedCompressionAlgorithmsServerToClient = new LinkedList<>(clientSupportedCompressionAlgorithmsClientToServer);
        serverSupportedCompressionAlgorithmsClientToServer = new LinkedList<>(clientSupportedCompressionAlgorithmsClientToServer);

        clientSupportedLanguagesClientToServer = new LinkedList<>();
        clientSupportedLanguagesClientToServer.add(Language.None);
        clientSupportedLanguagesServerToClient = new LinkedList<>(clientSupportedLanguagesClientToServer);

        serverSupportedLanguagesServerToClient = new LinkedList<>(clientSupportedLanguagesClientToServer);
        serverSupportedLanguagesClientToServer = new LinkedList<>(clientSupportedLanguagesClientToServer);

        clientFirstKeyExchangePacketFollows = (byte) 0;
        serverFirstKeyExchangePacketFollows = (byte) 0;

        clientReserved = 0;
        serverReserved = 0;
        
        
//        defaultHostKeyType = PublicKeyAuthenticationAlgorithm.ssh_dss.getValue();
//
//        //TODO create default private/public keypairs and store them in constants
//        defaultRsaExponent = BigInteger.valueOf(65537);
//        defaultRsaModulus = BigInteger.valueOf(13);
//        defaultServerEcdhPublicKey = new byte[]{1, 2};
//        defaultClientEcdhPublicKey = new byte[]{3, 4};
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
// BEGIN_GENERATED

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

    public List<MACAlgorithm> getClientSupportedMacAlgorithmsClientToServer() {
        return clientSupportedMacAlgorithmsClientToServer;
    }

    public List<MACAlgorithm> getClientSupportedMacAlgorithmsServerToClient() {
        return clientSupportedMacAlgorithmsServerToClient;
    }

    public List<MACAlgorithm> getServerSupportedMacAlgorithmsServerToClient() {
        return serverSupportedMacAlgorithmsServerToClient;
    }

    public List<MACAlgorithm> getServerSupportedMacAlgorithmsClientToServer() {
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

    public byte getClientFirstKeyExchangePacketFollows() {
        return clientFirstKeyExchangePacketFollows;
    }

    public byte getServerFirstKeyExchangePacketFollows() {
        return serverFirstKeyExchangePacketFollows;
    }

    public int getClientReserved() {
        return clientReserved;
    }

    public int getServerReserved() {
        return serverReserved;
    }

// END GENERATED

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

    
}
