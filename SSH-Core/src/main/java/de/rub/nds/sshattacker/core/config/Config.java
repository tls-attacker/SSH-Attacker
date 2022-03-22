/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.config;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.modifiablevariable.util.UnformattedByteArrayAdapter;
import de.rub.nds.sshattacker.core.connection.Channel;
import de.rub.nds.sshattacker.core.connection.InboundConnection;
import de.rub.nds.sshattacker.core.connection.OutboundConnection;
import de.rub.nds.sshattacker.core.constants.*;
import de.rub.nds.sshattacker.core.crypto.keys.*;
import de.rub.nds.sshattacker.core.workflow.factory.WorkflowTraceType;
import de.rub.nds.sshattacker.core.workflow.filter.FilterType;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.Serializable;
import java.lang.reflect.Field;
import java.math.BigInteger;
import java.security.Security;
import java.util.*;
import java.util.stream.Collectors;
import javax.xml.bind.annotation.*;
import javax.xml.bind.annotation.adapters.XmlJavaTypeAdapter;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

@XmlRootElement(name = "config")
@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(propOrder = {})
public class Config implements Serializable {

    private static final Logger LOGGER = LogManager.getLogger();

    private static final String DEFAULT_CONFIG_FILE = "/default_config.xml";

    private static final ConfigCache DEFAULT_CONFIG_CACHE;

    static {
        DEFAULT_CONFIG_CACHE = new ConfigCache(createConfig());
        Security.addProvider(new BouncyCastleProvider());
    }

    private final String clientVersion;

    private final String clientComment;

    private final String clientEndOfMessageSequence;

    private final String serverVersion;

    private final String serverComment;

    private final String serverEndOfMessageSequence;

    @XmlJavaTypeAdapter(UnformattedByteArrayAdapter.class)
    private final byte[] clientCookie;

    @XmlJavaTypeAdapter(UnformattedByteArrayAdapter.class)
    private final byte[] serverCookie;

    @XmlElement(name = "clientSupportedKeyExchangeAlgorithm")
    @XmlElementWrapper
    private List<KeyExchangeAlgorithm> clientSupportedKeyExchangeAlgorithms;

    @XmlElement(name = "serverSupportedKeyExchangeAlgorithm")
    @XmlElementWrapper
    private final List<KeyExchangeAlgorithm> serverSupportedKeyExchangeAlgorithms;

    @XmlElement(name = "clientSupportedHostKeyAlgorithm")
    @XmlElementWrapper
    private final List<PublicKeyAlgorithm> clientSupportedHostKeyAlgorithms;

    @XmlElement(name = "serverSupportedHostKeyAlgorithm")
    @XmlElementWrapper
    private final List<PublicKeyAlgorithm> serverSupportedHostKeyAlgorithms;

    @XmlElement(name = "clientSupportedEncryptionAlgorithmClientToServer")
    @XmlElementWrapper
    private final List<EncryptionAlgorithm> clientSupportedEncryptionAlgorithmsClientToServer;

    @XmlElement(name = "clientSupportedEncryptionAlgorithmServerToClient")
    @XmlElementWrapper
    private final List<EncryptionAlgorithm> clientSupportedEncryptionAlgorithmsServerToClient;

    @XmlElement(name = "serverSupportedEncryptionAlgorithmServerToClient")
    @XmlElementWrapper
    private final List<EncryptionAlgorithm> serverSupportedEncryptionAlgorithmsServerToClient;

    @XmlElement(name = "serverSupportedEncryptionAlgorithmClientToServer")
    @XmlElementWrapper
    private final List<EncryptionAlgorithm> serverSupportedEncryptionAlgorithmsClientToServer;

    @XmlElement(name = "clientSupportedMacAlgorithmClientToServer")
    @XmlElementWrapper
    private final List<MacAlgorithm> clientSupportedMacAlgorithmsClientToServer;

    @XmlElement(name = "clientSupportedMacAlgorithmServerToClient")
    @XmlElementWrapper
    private final List<MacAlgorithm> clientSupportedMacAlgorithmsServerToClient;

    @XmlElement(name = "serverSupportedMacAlgorithmServerToClient")
    @XmlElementWrapper
    private final List<MacAlgorithm> serverSupportedMacAlgorithmsServerToClient;

    @XmlElement(name = "serverSupportedMacAlgorithmClientToServer")
    @XmlElementWrapper
    private final List<MacAlgorithm> serverSupportedMacAlgorithmsClientToServer;

    @XmlElement(name = "clientSupportedCompressionMethodClientToServer")
    @XmlElementWrapper
    private final List<CompressionMethod> clientSupportedCompressionMethodsClientToServer;

    @XmlElement(name = "clientSupportedCompressionMethodServerToClient")
    @XmlElementWrapper
    private final List<CompressionMethod> clientSupportedCompressionMethodsServerToClient;

    @XmlElement(name = "serverSupportedCompressionMethodServerToClient")
    @XmlElementWrapper
    private final List<CompressionMethod> serverSupportedCompressionMethodsServerToClient;

    @XmlElement(name = "serverSupportedCompressionMethodClientToServer")
    @XmlElementWrapper
    private final List<CompressionMethod> serverSupportedCompressionMethodsClientToServer;

    @XmlElement(name = "clientSupportedLanguageClientToServer")
    @XmlElementWrapper
    private final List<String> clientSupportedLanguagesClientToServer;

    @XmlElement(name = "clientSupportedLanguageServerToClient")
    @XmlElementWrapper
    private final List<String> clientSupportedLanguagesServerToClient;

    @XmlElement(name = "serverSupportedLanguageServerToClient")
    @XmlElementWrapper
    private final List<String> serverSupportedLanguagesServerToClient;

    @XmlElement(name = "serverSupportedLanguageClientToServer")
    @XmlElementWrapper
    private final List<String> serverSupportedLanguagesClientToServer;

    private final boolean clientFirstKeyExchangePacketFollows;

    private final boolean serverFirstKeyExchangePacketFollows;

    private final int clientReserved;

    private final int serverReserved;

    @XmlElement(name = "hostKey")
    @XmlElementWrapper
    private final List<SshPublicKey<?, ?>> serverHostKeys;

    private final Integer dhGexMinimalGroupSize;

    private final Integer dhGexPreferredGroupSize;

    private final Integer dhGexMaximalGroupSize;

    private final NamedDHGroup defaultDhKeyExchangeGroup;

    private final NamedGroup defaultEcdhKeyExchangeGroup;

    private final KeyExchangeAlgorithm defaultRsaKeyExchangeAlgorithm;

    private final CustomRsaPublicKey rsaKeyExchangeTransientPublicKey;

    private AuthenticationMethod authenticationMethod;

    private String serviceName;

    private String username;

    private String password;

    private ChannelRequestType channelRequestType;

    private String channelCommand;

    private Channel defaultChannel;

    private byte replyWanted;

    private String defaultVariableName;

    private String defaultVariableValue;

    private SignalType defaultSignalType;

    /** Default Connection to use when running as Client */
    private OutboundConnection defaultClientConnection;

    /** Default Connection to use when running as Server */
    private InboundConnection defaultServerConnection;

    private RunningModeType defaultRunningMode = RunningModeType.CLIENT;

    private Boolean filtersKeepUserSettings = true;

    private String workflowInput = null;

    private WorkflowTraceType workflowTraceType;

    private List<FilterType> outputFilters;

    private String workflowOutput = null;

    private Boolean applyFiltersInPlace;

    private Boolean workflowExecutorShouldOpen = true;

    private Boolean stopActionsAfterDisconnect = true;

    private Boolean stopActionsAfterIOException = true;

    private Boolean workflowExecutorShouldClose = true;

    private Boolean resetWorkflowtracesBeforeSaving = false;

    private String configOutput = null;

    private Boolean enforceSettings = false;

    /**
     * If set to true, sending or receiving a NewKeysMessage automatically enables the encryption
     * for the corresponding transport direction. If set to false, encryption must be enabled
     * manually by calling the corresponding methods on the state.
     */
    private Boolean enableEncryptionOnNewKeysMessage = false;

    private ChooserType chooserType = ChooserType.DEFAULT;

    public Config() {

        defaultClientConnection = new OutboundConnection("client", 65222, "localhost");
        defaultServerConnection = new InboundConnection("server", 65222, "localhost");

        clientVersion = "SSH-2.0-OpenSSH_8.2p1";
        clientComment = "";
        serverVersion = clientVersion;
        serverComment = clientComment;
        clientEndOfMessageSequence = "\r\n";
        serverEndOfMessageSequence = "\r\n";

        clientCookie = ArrayConverter.hexStringToByteArray("00000000000000000000000000000000");
        serverCookie = ArrayConverter.hexStringToByteArray("00000000000000000000000000000000");

        // Default values for cryptographic parameters are taken from OpenSSH 8.2p1
        clientSupportedKeyExchangeAlgorithms =
                Arrays.stream(
                                new KeyExchangeAlgorithm[] {
                                    KeyExchangeAlgorithm.CURVE25519_SHA256,
                                    KeyExchangeAlgorithm.CURVE25519_SHA256_LIBSSH_ORG,
                                    KeyExchangeAlgorithm.ECDH_SHA2_NISTP256,
                                    KeyExchangeAlgorithm.ECDH_SHA2_NISTP384,
                                    KeyExchangeAlgorithm.ECDH_SHA2_NISTP521,
                                    KeyExchangeAlgorithm.DIFFIE_HELLMAN_GROUP_EXCHANGE_SHA256,
                                    KeyExchangeAlgorithm.DIFFIE_HELLMAN_GROUP16_SHA512,
                                    KeyExchangeAlgorithm.DIFFIE_HELLMAN_GROUP18_SHA512,
                                    KeyExchangeAlgorithm.DIFFIE_HELLMAN_GROUP14_SHA256
                                })
                        .collect(Collectors.toCollection(LinkedList::new));
        serverSupportedKeyExchangeAlgorithms =
                new LinkedList<>(clientSupportedKeyExchangeAlgorithms);

        // We don't support CERT_V01 or SK (U2F) host keys (yet), only listed for completeness
        clientSupportedHostKeyAlgorithms =
                Arrays.stream(
                                new PublicKeyAlgorithm[] {
                                    // PublicKeyAlgorithm.ECDSA_SHA2_NISTP256_CERT_V01_OPENSSH_COM,
                                    // PublicKeyAlgorithm.ECDSA_SHA2_NISTP384_CERT_V01_OPENSSH_COM,
                                    // PublicKeyAlgorithm.ECDSA_SHA2_NISTP521_CERT_V01_OPENSSH_COM,
                                    // PublicKeyAlgorithm.SK_ECDSA_SHA2_NISTP256_CERT_V01_OPENSSH_COM,
                                    // PublicKeyAlgorithm.SSH_ED25519_CERT_V01_OPENSSH_COM,
                                    // PublicKeyAlgorithm.SK_SSH_ED25519_CERT_V01_OPENSSH_COM,
                                    // PublicKeyAlgorithm.RSA_SHA2_512_CERT_V01_OPENSSH_COM,
                                    // PublicKeyAlgorithm.RSA_SHA2_256_CERT_V01_OPENSSH_COM,
                                    // PublicKeyAlgorithm.SSH_RSA_CERT_V01_OPENSSH_COM,
                                    PublicKeyAlgorithm.ECDSA_SHA2_NISTP256,
                                    PublicKeyAlgorithm.ECDSA_SHA2_NISTP384,
                                    PublicKeyAlgorithm.ECDSA_SHA2_NISTP521,
                                    // PublicKeyAlgorithm.SK_ECDSA_SHA2_NISTP256_OPENSSH_COM,
                                    PublicKeyAlgorithm.SSH_ED25519,
                                    // PublicKeyAlgorithm.SK_SSH_ED25519_OPENSSH_COM,
                                    PublicKeyAlgorithm.RSA_SHA2_512,
                                    PublicKeyAlgorithm.RSA_SHA2_256,
                                    PublicKeyAlgorithm.SSH_RSA
                                })
                        .collect(Collectors.toCollection(LinkedList::new));
        serverSupportedHostKeyAlgorithms = new LinkedList<>(clientSupportedHostKeyAlgorithms);

        clientSupportedEncryptionAlgorithmsClientToServer =
                Arrays.stream(
                                new EncryptionAlgorithm[] {
                                    EncryptionAlgorithm.CHACHA20_POLY1305_OPENSSH_COM,
                                    EncryptionAlgorithm.AES128_CTR,
                                    EncryptionAlgorithm.AES192_CTR,
                                    EncryptionAlgorithm.AES256_CTR,
                                    EncryptionAlgorithm.AES128_GCM_OPENSSH_COM,
                                    EncryptionAlgorithm.AES256_GCM_OPENSSH_COM
                                })
                        .collect(Collectors.toCollection(LinkedList::new));
        clientSupportedEncryptionAlgorithmsServerToClient =
                new LinkedList<>(clientSupportedEncryptionAlgorithmsClientToServer);
        serverSupportedEncryptionAlgorithmsClientToServer =
                new LinkedList<>(clientSupportedEncryptionAlgorithmsClientToServer);
        serverSupportedEncryptionAlgorithmsServerToClient =
                new LinkedList<>(clientSupportedEncryptionAlgorithmsClientToServer);

        clientSupportedMacAlgorithmsClientToServer =
                Arrays.stream(
                                new MacAlgorithm[] {
                                    MacAlgorithm.UMAC_64_ETM_OPENSSH_COM,
                                    MacAlgorithm.UMAC_128_ETM_OPENSSH_COM,
                                    MacAlgorithm.HMAC_SHA2_256_ETM_OPENSSH_COM,
                                    MacAlgorithm.HMAC_SHA2_512_ETM_OPENSSH_COM,
                                    MacAlgorithm.HMAC_SHA1_ETM_OPENSSH_COM,
                                    MacAlgorithm.UMAC_64_OPENSSH_COM,
                                    MacAlgorithm.UMAC_128_OPENSSH_COM,
                                    MacAlgorithm.HMAC_SHA2_256,
                                    MacAlgorithm.HMAC_SHA2_512,
                                    MacAlgorithm.HMAC_SHA1
                                })
                        .collect(Collectors.toCollection(LinkedList::new));
        clientSupportedMacAlgorithmsServerToClient =
                new LinkedList<>(clientSupportedMacAlgorithmsClientToServer);
        serverSupportedMacAlgorithmsServerToClient =
                new LinkedList<>(clientSupportedMacAlgorithmsClientToServer);
        serverSupportedMacAlgorithmsClientToServer =
                new LinkedList<>(clientSupportedMacAlgorithmsClientToServer);

        clientSupportedCompressionMethodsClientToServer =
                Arrays.stream(
                                new CompressionMethod[] {
                                    CompressionMethod.NONE,
                                    CompressionMethod.ZLIB_OPENSSH_COM,
                                    CompressionMethod.ZLIB
                                })
                        .collect(Collectors.toCollection(LinkedList::new));
        clientSupportedCompressionMethodsServerToClient =
                new LinkedList<>(clientSupportedCompressionMethodsClientToServer);
        serverSupportedCompressionMethodsServerToClient =
                new LinkedList<>(clientSupportedCompressionMethodsClientToServer);
        serverSupportedCompressionMethodsClientToServer =
                new LinkedList<>(clientSupportedCompressionMethodsClientToServer);

        clientSupportedLanguagesClientToServer = new LinkedList<>();
        clientSupportedLanguagesServerToClient =
                new LinkedList<>(clientSupportedLanguagesClientToServer);
        serverSupportedLanguagesServerToClient =
                new LinkedList<>(clientSupportedLanguagesClientToServer);
        serverSupportedLanguagesClientToServer =
                new LinkedList<>(clientSupportedLanguagesClientToServer);

        clientFirstKeyExchangePacketFollows = false;
        serverFirstKeyExchangePacketFollows = false;

        dhGexMinimalGroupSize = 2048;
        dhGexPreferredGroupSize = 4096;
        dhGexMaximalGroupSize = 8192;

        defaultDhKeyExchangeGroup = NamedDHGroup.GROUP14;
        defaultEcdhKeyExchangeGroup = NamedGroup.SECP256R1;

        defaultRsaKeyExchangeAlgorithm = KeyExchangeAlgorithm.RSA2048_SHA256;
        rsaKeyExchangeTransientPublicKey =
                new CustomRsaPublicKey(
                        new BigInteger("01001", 16),
                        new BigInteger(
                                "00FD786F7BB51AC8B619430613F84251BEDEF47216786EE72025D02DC6E4FF923193E63DE937"
                                        + "986925263360EBAF68990C73CA78B99EC24822FDB923461AD6925A4AD4EBAD370DA5B8AD9D9A4AD0E3E4240"
                                        + "43B7705D55DC52429D3DDD9F9F2E3DC618BF87C3519F5BB7C908C4B76CB72D366C5E32077E38DEF1780845B"
                                        + "C950DFDF82C02CAFC1A8EE3535E491F33A8DC45EF515B56E305BC4BC124857D6662DB2C532840383F10C8EE"
                                        + "CA47029FC31143ACA4DE26C905E1291F778A6FBC0BDB219F775B33F3114C2ED1B64CC8E19ABC10530589677"
                                        + "8F7F686F82713E9198B19F70FF73674603B839B90ECE883D81DFB32DA3F9363A3207A639523F90EEE730B49F"
                                        + "65",
                                16));

        // An OpenSSL generated 2048 bit RSA keypair is currently being used as the default host key
        serverHostKeys = new ArrayList<>();
        serverHostKeys.add(
                new SshPublicKey<>(
                        PublicKeyFormat.SSH_RSA,
                        new CustomRsaPublicKey(
                                new BigInteger("010001", 16),
                                new BigInteger(
                                        "00D9F6BFFAB8BC79C6E9AB6C3D4593F561CC93B41A70B9A750045ED0AC09"
                                                + "6EF4A6A8C7B2AAA4F44459481319AE956934BF9D5C5AD7C004ADE0B81E43"
                                                + "75FD1DF8797DF6F3CA130ED8A2A9B6E94467A05D97A0F8380A4CBB75FC5E"
                                                + "5C303433B61750063D3801D5C90658ACAEE140B09F95A0FD8886EFAE16EA"
                                                + "B779DF82E6A12C1BE011FECB417C788B72C42948AB54CCE1E8119CFB78E1"
                                                + "3B06090CEBF6D3806854FE09F03B20BA92505058EC64C44F0B4DA0BAE71D"
                                                + "52EDA11AB67F4B54D9FCEFE1FACEB520D595FFA33502FB91423EBD972F26"
                                                + "150715CB0E648F715E6E5E8FC9D8FA55E9DE0652CF85D7928B235486F54A"
                                                + "3F3EE64B04888B898864B08200A9E22909",
                                        16)),
                        new CustomRsaPrivateKey(
                                new BigInteger(
                                        "7AAB5898AEE7C451A2A90B9DE04EC947656FAB69460FF68E1E278EA1841D"
                                                + "A22B39CA4A4FA7CEA1B8EDCB7224C38A1659D1226D2E07AF9A7C62A305AC"
                                                + "9DEC042FBC290443B23E24C64765DE1AD58777A522BF102B1BCC5536D794"
                                                + "62BCBE6DB8E91CD9CF6F98F62E5031BFAA9E51C93ED900579A39C26CBB64"
                                                + "CF7E6F998513E20B4B2A4DD36D4F6F074A0FDB04232FA6EDAB89A1B32BA5"
                                                + "2214696BDA66C4518A73F92807DD088AB11263519885A0CD6A42B6D9EAE9"
                                                + "EBD13241EDC4EB7205AE838A5EF7AE280D36410057B38ED05CEBA75F92AC"
                                                + "DF40226164BB3A0C4312B65A8C2FBA85CDB7CC5F77F53C45F64409AFC460"
                                                + "210C8EE4DAB818F009172387ED00E141",
                                        16),
                                new BigInteger(
                                        "00D9F6BFFAB8BC79C6E9AB6C3D4593F561CC93B41A70B9A750045ED0AC09"
                                                + "6EF4A6A8C7B2AAA4F44459481319AE956934BF9D5C5AD7C004ADE0B81E43"
                                                + "75FD1DF8797DF6F3CA130ED8A2A9B6E94467A05D97A0F8380A4CBB75FC5E"
                                                + "5C303433B61750063D3801D5C90658ACAEE140B09F95A0FD8886EFAE16EA"
                                                + "B779DF82E6A12C1BE011FECB417C788B72C42948AB54CCE1E8119CFB78E1"
                                                + "3B06090CEBF6D3806854FE09F03B20BA92505058EC64C44F0B4DA0BAE71D"
                                                + "52EDA11AB67F4B54D9FCEFE1FACEB520D595FFA33502FB91423EBD972F26"
                                                + "150715CB0E648F715E6E5E8FC9D8FA55E9DE0652CF85D7928B235486F54A"
                                                + "3F3EE64B04888B898864B08200A9E22909",
                                        16))));
        // SSH enforces the use of 1024 / 160 bit DSA keys as per RFC 4253 Sec. 6.6
        serverHostKeys.add(
                new SshPublicKey<>(
                        PublicKeyFormat.SSH_DSS,
                        new CustomDsaPublicKey(
                                new BigInteger(
                                        "008BD081A858028A729F0C04E0788C06BC5B2EA8B880A203986C90E92D20"
                                                + "322670248A305A3217737BF0256EFFD53CC512993F137A4F64162AF4F3E6"
                                                + "AA64D348343C86D1B3D18CAE017A48FD2FFA56A9DFC70D18BE8958938768"
                                                + "995AFD952719DE2066B0A7E3D90948D4E0437BD1A5C94F1A1FBBADDCEA3A"
                                                + "338E96A4CACCF4A855",
                                        16),
                                new BigInteger("00B971EBD0321EEC38C15E01FD9C773CCA23E66879", 16),
                                new BigInteger(
                                        "259DC09E04AD1818271F3E676B17A98B6F7B1D08B43B51FAEF06D2C9F921"
                                                + "0667ED3C14ABEBEE372D1F325C11C0304AE8B9BAC8914619CA05165BAE2B"
                                                + "E49BAD5DD8ECB8129CDDD2941D6DDF53C7D53A5FB9D88B58F362034CA6A1"
                                                + "3929D28942D0054FFA4166D3DDDE0B2FE2E4A0342A827DEF6B6FECDB0614"
                                                + "8ED403D3FC9C4C79",
                                        16),
                                new BigInteger(
                                        "1433495B5BB346BEB6A783DA2ADF1C5CFE946146E4A461B2A658CEC29DA2"
                                                + "1496A6D69119026059D0C2557D535E664A0F10B4DB006601D8848EA6B92F"
                                                + "C6313B03103C9C3C6F0ED55CB46EEC8B0FE0007D2411F46676A8761DADAA"
                                                + "171351322D29487E9AE8738C354DD04FFEACA50503AFEC8F0610A679FF81"
                                                + "6EFD9B162F152BDA",
                                        16)),
                        new CustomDsaPrivateKey(
                                new BigInteger(
                                        "008BD081A858028A729F0C04E0788C06BC5B2EA8B880A203986C90E92D20"
                                                + "322670248A305A3217737BF0256EFFD53CC512993F137A4F64162AF4F3E6"
                                                + "AA64D348343C86D1B3D18CAE017A48FD2FFA56A9DFC70D18BE8958938768"
                                                + "995AFD952719DE2066B0A7E3D90948D4E0437BD1A5C94F1A1FBBADDCEA3A"
                                                + "338E96A4CACCF4A855",
                                        16),
                                new BigInteger("00B971EBD0321EEC38C15E01FD9C773CCA23E66879", 16),
                                new BigInteger(
                                        "259DC09E04AD1818271F3E676B17A98B6F7B1D08B43B51FAEF06D2C9F921"
                                                + "0667ED3C14ABEBEE372D1F325C11C0304AE8B9BAC8914619CA05165BAE2B"
                                                + "E49BAD5DD8ECB8129CDDD2941D6DDF53C7D53A5FB9D88B58F362034CA6A1"
                                                + "3929D28942D0054FFA4166D3DDDE0B2FE2E4A0342A827DEF6B6FECDB0614"
                                                + "8ED403D3FC9C4C79",
                                        16),
                                new BigInteger("7C6B4E2B32192EFC09B7CB12D85CBB4141EF7348", 16))));

        clientReserved = 0;
        serverReserved = 0;

        authenticationMethod = AuthenticationMethod.PASSWORD;
        serviceName = "ssh-userauth";
        username = "sshattacker";
        password = "bydahirsch";
        defaultChannel =
                new Channel(
                        ChannelType.SESSION,
                        1337,
                        Integer.MAX_VALUE,
                        Integer.MAX_VALUE,
                        0,
                        Integer.MAX_VALUE,
                        Integer.MAX_VALUE,
                        true);
        replyWanted = 0;
        channelCommand = "nc -l -p 13370";
        defaultVariableName = "PATH";
        defaultVariableValue = "usr/local/bin";
        defaultSignalType = SignalType.SIGINT;

        workflowTraceType = null;
        outputFilters = new ArrayList<>();
        outputFilters.add(FilterType.DEFAULT);
        applyFiltersInPlace = false;
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
            if (!field.getName().equals("LOGGER") && !field.getType().isPrimitive()) {
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

    public String getClientEndOfMessageSequence() {
        return clientEndOfMessageSequence;
    }

    public String getServerEndOfMessageSequence() {
        return serverEndOfMessageSequence;
    }

    public List<KeyExchangeAlgorithm> getClientSupportedKeyExchangeAlgorithms() {
        return clientSupportedKeyExchangeAlgorithms;
    }

    public void setClientSupportedKeyExchangeAlgorithms(
            List<KeyExchangeAlgorithm> clientSupportedKeyExchangeAlgorithms) {
        this.clientSupportedKeyExchangeAlgorithms = clientSupportedKeyExchangeAlgorithms;
    }

    public List<KeyExchangeAlgorithm> getServerSupportedKeyExchangeAlgorithms() {
        return serverSupportedKeyExchangeAlgorithms;
    }

    public List<PublicKeyAlgorithm> getClientSupportedHostKeyAlgorithms() {
        return clientSupportedHostKeyAlgorithms;
    }

    public List<PublicKeyAlgorithm> getServerSupportedHostKeyAlgorithms() {
        return serverSupportedHostKeyAlgorithms;
    }

    public List<EncryptionAlgorithm> getClientSupportedEncryptionAlgorithmsClientToServer() {
        return clientSupportedEncryptionAlgorithmsClientToServer;
    }

    public List<EncryptionAlgorithm> getClientSupportedEncryptionAlgorithmsServerToClient() {
        return clientSupportedEncryptionAlgorithmsServerToClient;
    }

    public List<EncryptionAlgorithm> getServerSupportedEncryptionAlgorithmsServerToClient() {
        return serverSupportedEncryptionAlgorithmsServerToClient;
    }

    public List<EncryptionAlgorithm> getServerSupportedEncryptionAlgorithmsClientToServer() {
        return serverSupportedEncryptionAlgorithmsClientToServer;
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

    public List<CompressionMethod> getClientSupportedCompressionMethodsClientToServer() {
        return clientSupportedCompressionMethodsClientToServer;
    }

    public List<CompressionMethod> getClientSupportedCompressionMethodsServerToClient() {
        return clientSupportedCompressionMethodsServerToClient;
    }

    public List<CompressionMethod> getServerSupportedCompressionMethodsServerToClient() {
        return serverSupportedCompressionMethodsServerToClient;
    }

    public List<CompressionMethod> getServerSupportedCompressionMethodsClientToServer() {
        return serverSupportedCompressionMethodsClientToServer;
    }

    public List<String> getClientSupportedLanguagesClientToServer() {
        return clientSupportedLanguagesClientToServer;
    }

    public List<String> getClientSupportedLanguagesServerToClient() {
        return clientSupportedLanguagesServerToClient;
    }

    public List<String> getServerSupportedLanguagesServerToClient() {
        return serverSupportedLanguagesServerToClient;
    }

    public List<String> getServerSupportedLanguagesClientToServer() {
        return serverSupportedLanguagesClientToServer;
    }

    public boolean getClientFirstKeyExchangePacketFollows() {
        return clientFirstKeyExchangePacketFollows;
    }

    public boolean getServerFirstKeyExchangePacketFollows() {
        return serverFirstKeyExchangePacketFollows;
    }

    public int getClientReserved() {
        return clientReserved;
    }

    public int getServerReserved() {
        return serverReserved;
    }

    public Integer getDhGexMinimalGroupSize() {
        return dhGexMinimalGroupSize;
    }

    public Integer getDhGexPreferredGroupSize() {
        return dhGexPreferredGroupSize;
    }

    public Integer getDhGexMaximalGroupSize() {
        return dhGexMaximalGroupSize;
    }

    public NamedDHGroup getDefaultDhKeyExchangeGroup() {
        return defaultDhKeyExchangeGroup;
    }

    public NamedGroup getDefaultEcdhKeyExchangeGroup() {
        return defaultEcdhKeyExchangeGroup;
    }

    public KeyExchangeAlgorithm getDefaultRsaKeyExchangeAlgorithm() {
        return defaultRsaKeyExchangeAlgorithm;
    }

    public CustomRsaPublicKey getRsaKeyExchangeTransientPublicKey() {
        return rsaKeyExchangeTransientPublicKey;
    }

    public List<SshPublicKey<?, ?>> getServerHostKeys() {
        return serverHostKeys;
    }

    public AuthenticationMethod getAuthenticationMethod() {
        return authenticationMethod;
    }

    public void setAuthenticationMethod(AuthenticationMethod authenticationMethod) {
        this.authenticationMethod = authenticationMethod;
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

    public ChannelRequestType getChannelRequestType() {
        return channelRequestType;
    }

    public void setChannelRequestType(ChannelRequestType channelRequestType) {
        this.channelRequestType = channelRequestType;
    }

    public Boolean isFiltersKeepUserSettings() {
        return filtersKeepUserSettings;
    }

    public void setFiltersKeepUserSettings(Boolean filtersKeepUserSettings) {
        this.filtersKeepUserSettings = filtersKeepUserSettings;
    }

    public void setWorkflowInput(String workflowInput) {
        this.workflowInput = workflowInput;
    }

    public String getWorkflowInput() {
        return workflowInput;
    }

    public WorkflowTraceType getWorkflowTraceType() {
        return workflowTraceType;
    }

    public void setWorkflowTraceType(WorkflowTraceType workflowTraceType) {
        this.workflowTraceType = workflowTraceType;
    }

    public List<FilterType> getOutputFilters() {
        return outputFilters;
    }

    public void setOutputFilters(List<FilterType> outputFilters) {
        this.outputFilters = outputFilters;
    }

    public String getWorkflowOutput() {
        return workflowOutput;
    }

    public void setWorkflowOutput(String workflowOutput) {
        this.workflowOutput = workflowOutput;
    }

    public Boolean isApplyFiltersInPlace() {
        return applyFiltersInPlace;
    }

    public void setApplyFiltersInPlace(Boolean applyFiltersInPlace) {
        this.applyFiltersInPlace = applyFiltersInPlace;
    }

    public Boolean getWorkflowExecutorShouldOpen() {
        return workflowExecutorShouldOpen;
    }

    public void setWorkflowExecutorShouldOpen(Boolean workflowExecutorShouldOpen) {
        this.workflowExecutorShouldOpen = workflowExecutorShouldOpen;
    }

    public Boolean getStopActionsAfterDisconnect() {
        return stopActionsAfterDisconnect;
    }

    public void setStopActionsAfterDisconnect(Boolean stopActionsAfterDisconnect) {
        this.stopActionsAfterDisconnect = stopActionsAfterDisconnect;
    }

    public Boolean getStopActionsAfterIOException() {
        return stopActionsAfterIOException;
    }

    public void setStopActionsAfterIOException(Boolean stopActionsAfterIOException) {
        this.stopActionsAfterIOException = stopActionsAfterIOException;
    }

    public Boolean getWorkflowExecutorShouldClose() {
        return workflowExecutorShouldClose;
    }

    public void setWorkflowExecutorShouldClose(Boolean workflowExecutorShouldClose) {
        this.workflowExecutorShouldClose = workflowExecutorShouldClose;
    }

    public Boolean getResetWorkflowtracesBeforeSaving() {
        return resetWorkflowtracesBeforeSaving;
    }

    public void setResetWorkflowtracesBeforeSaving(Boolean resetWorkflowtracesBeforeSaving) {
        this.resetWorkflowtracesBeforeSaving = resetWorkflowtracesBeforeSaving;
    }

    public String getConfigOutput() {
        return configOutput;
    }

    public void setConfigOutput(String configOutput) {
        this.configOutput = configOutput;
    }

    public Boolean getEnforceSettings() {
        return enforceSettings;
    }

    public void setEnforceSettings(Boolean enforceSettings) {
        this.enforceSettings = enforceSettings;
    }

    public String getServiceName() {
        return serviceName;
    }

    public void setServiceName(String serviceName) {
        this.serviceName = serviceName;
    }

    public Boolean getEnableEncryptionOnNewKeysMessage() {
        return enableEncryptionOnNewKeysMessage;
    }

    public void setEnableEncryptionOnNewKeysMessage(Boolean enableEncryptionOnNewKeysMessage) {
        this.enableEncryptionOnNewKeysMessage = enableEncryptionOnNewKeysMessage;
    }

    public ChooserType getChooserType() {
        return chooserType;
    }

    public void setChooserType(ChooserType chooserType) {
        this.chooserType = chooserType;
    }

    public Channel getDefaultChannel() {
        return defaultChannel;
    }

    public void setDefaultChannel(Channel defaultChannel) {
        this.defaultChannel = defaultChannel;
    }

    public String getDefaultVariableValue() {
        return defaultVariableValue;
    }

    public void setDefaultVariableValue(String defaultVariableValue) {
        this.defaultVariableValue = defaultVariableValue;
    }

    public SignalType getDefaultSignalType() {
        return defaultSignalType;
    }

    public void setDefaultSignalType(SignalType defaultSignalType) {
        this.defaultSignalType = defaultSignalType;
    }

    public String getDefaultVariableName() {
        return defaultVariableName;
    }

    public void setDefaultVariableName(String defaultVariableName) {
        this.defaultVariableName = defaultVariableName;
    }
}
