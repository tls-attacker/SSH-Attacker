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

//    /**
//     * From ClientInitMessage
//     */
//    private String clientVersion;
//    private String clientComment;
//    private String serverVersion;
//    private String serverComment;
//
//    /**
//     * From KeyExchangeInitMessage
//     */
//    private byte[] clientCookie;
//    private byte[] serverCookie;
//    private List<KeyExchangeAlgorithm> supportedKeyExchangeAlgorithms;
//    private List<PublicKeyAuthenticationAlgorithm> PublicKeyAuthenticationAlgorithms;
//    private List<EncryptionAlgorithm> supportedEncryptionAlgorithmsClientToServer;
//    private List<EncryptionAlgorithm> supportedEncryptionAlgorithmsServerToClient;
//    private List<MACAlgorithm> supportedMacAlgorithmsClientToServer;
//    private List<MACAlgorithm> supportedMacAlgorithmsServerToClient;
//    private List<CompressionAlgorithm> supportedCompressionAlgorithmsClientToServer;
//    private List<CompressionAlgorithm> supportedCompressionAlgorithmsServerToClient;
//    private List<Language> supportedLanguagesClientToServer;
//    private List<Language> supportedLanguagesServerToClient;
//    private byte defaultFirstKeyExchangePacketFollows;
//    private int defaultReserved;
//
//    /**
//     * From ECDHKeyExchangeInitMessage
//     */
//    private byte[] defaultClientEcdhPublicKey;
//
//    /**
//     * From ECDHKeyExchangeReplyMessage
//     */
//    private String defaultHostKeyType;
//    private BigInteger defaultRsaExponent;
//    private BigInteger defaultRsaModulus;
//    private byte[] defaultServerEcdhPublicKey;
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
    private byte clientFirstKeyExchangePacketFollows;
    private byte serverFirstKeyExchangePacketFollows;
    private int clientReserved;
    private int serverReserved;
// END GENERATED
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

        clientSupportedCipherAlgorithmsSending = new LinkedList<>();
        clientSupportedCipherAlgorithmsSending.add(EncryptionAlgorithm.tdes_cbc);
        clientSupportedCipherAlgorithmsReceiving = new LinkedList<>(clientSupportedCipherAlgorithmsSending);

        serverSupportedCipherAlgorithmsReceiving = new LinkedList<>(clientSupportedCipherAlgorithmsSending);
        serverSupportedCipherAlgorithmsSending = new LinkedList<>(clientSupportedCipherAlgorithmsSending);

        clientSupportedMacAlgorithmsSending = new LinkedList<>();
        clientSupportedMacAlgorithmsSending.add(MACAlgorithm.hmac_sha1);
        clientSupportedMacAlgorithmsReceiving = new LinkedList<>(clientSupportedMacAlgorithmsSending);

        serverSupportedMacAlgorithmsSending = new LinkedList<>(clientSupportedMacAlgorithmsSending);
        serverSupportedMacAlgorithmsReceiving = new LinkedList<>(clientSupportedMacAlgorithmsSending);

        clientSupportedCompressionAlgorithmsSending = new LinkedList<>();
        clientSupportedCompressionAlgorithmsSending.add(CompressionAlgorithm.none);
        clientSupportedCompressionAlgorithmsReceiving = new LinkedList<>(clientSupportedCompressionAlgorithmsSending);

        serverSupportedCompressionAlgorithmsSending = new LinkedList<>(clientSupportedCompressionAlgorithmsSending);
        serverSupportedCompressionAlgorithmsReceiving = new LinkedList<>(clientSupportedCompressionAlgorithmsSending);

        clientSupportedLanguagesSending = new LinkedList<>();
        clientSupportedLanguagesSending.add(Language.None);
        clientSupportedLanguagesReceiving = new LinkedList<>(clientSupportedLanguagesSending);

        serverSupportedLanguagesSending = new LinkedList<>(clientSupportedLanguagesSending);
        serverSupportedLanguagesReceiving = new LinkedList<>(clientSupportedLanguagesSending);

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
}
