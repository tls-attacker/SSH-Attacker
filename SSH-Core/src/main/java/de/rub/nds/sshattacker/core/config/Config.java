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
import de.rub.nds.sshattacker.core.connection.InboundConnection;
import de.rub.nds.sshattacker.core.connection.OutboundConnection;
import de.rub.nds.sshattacker.core.constants.*;
import de.rub.nds.sshattacker.core.crypto.ec.PointFormatter;
import de.rub.nds.sshattacker.core.crypto.hash.ExchangeHashInputHolder;
import de.rub.nds.sshattacker.core.crypto.keys.*;
import de.rub.nds.sshattacker.core.protocol.authentication.AuthenticationResponse;
import de.rub.nds.sshattacker.core.protocol.connection.ChannelDefaults;
import de.rub.nds.sshattacker.core.workflow.factory.WorkflowTraceType;
import de.rub.nds.sshattacker.core.workflow.filter.FilterType;
import jakarta.xml.bind.annotation.*;
import jakarta.xml.bind.annotation.adapters.XmlJavaTypeAdapter;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.Serializable;
import java.lang.reflect.Field;
import java.math.BigInteger;
import java.security.Security;
import java.util.*;
import java.util.stream.Collectors;
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

    // Invalid Curve Attack Additions
    // Mod
    private boolean isInvalidCurveAttack = false;

    private byte[] customEcPublicKey;
    private byte[] customEcPrivateKey;
    private BigInteger customSharedSecret;
    private byte[] exchangeHashSignatureServer;
    private ExchangeHashInputHolder exchangeHashInputHolderClient;

    public boolean getIsInvalidCurveAttack() {
        return isInvalidCurveAttack;
    }

    public void setInvalidCurveAttack(boolean isInvalidCurveAttack) {
        this.isInvalidCurveAttack = isInvalidCurveAttack;
    }

    public void setCustomEcPublicKey(byte[] customEcPublicKey) {
        this.customEcPublicKey = customEcPublicKey;
    }

    public void setCustomEcPrivateKey(byte[] customEcPrivateKey) {
        this.customEcPrivateKey = customEcPrivateKey;
    }

    public byte[] getCustomEcPublicKey() {
        return customEcPublicKey;
    }

    public byte[] getCustomEcPrivateKey() {
        return customEcPrivateKey;
    }

    public void setCustomSharedSecret(BigInteger customSharedSecret) {
        this.customSharedSecret = customSharedSecret;
    }

    public BigInteger getCustomSharedSecret() {
        return customSharedSecret;
    }

    public byte[] getExchangeHashSignatureServer() {
        return exchangeHashSignatureServer;
    }

    public void setExchangeHashSignatureServer(byte[] exchangeHashSignatureServer) {
        this.exchangeHashSignatureServer = exchangeHashSignatureServer;
    }

    public ExchangeHashInputHolder getExchangeHashInputHolderClient() {
        return exchangeHashInputHolderClient;
    }

    public void setExchangeHashInputHolderClient(
            ExchangeHashInputHolder exchangeHashInputHolderClient) {
        this.exchangeHashInputHolderClient = exchangeHashInputHolderClient;
    }

    // Mod end

    /** Default Connection to use when running as Client */
    private OutboundConnection defaultClientConnection;
    /** Default Connection to use when running as Server */
    private InboundConnection defaultServerConnection;
    /** The default running mode, when running the SSH-Attacker */
    private RunningModeType defaultRunningMode = RunningModeType.CLIENT;

    // region VersionExchange
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

    // region Pre-KeyExchange
    /** Client cookie containing 16 random bytes */
    @XmlJavaTypeAdapter(UnformattedByteArrayAdapter.class)
    private byte[] clientCookie;

    /** Server cookie containing 16 random bytes */
    @XmlJavaTypeAdapter(UnformattedByteArrayAdapter.class)
    private byte[] serverCookie;

    /** List of key exchange algorithms supported by the remote peer */
    @XmlElement(name = "clientSupportedKeyExchangeAlgorithm")
    @XmlElementWrapper
    private List<KeyExchangeAlgorithm> clientSupportedKeyExchangeAlgorithms;

    /** List of key exchange algorithms supported by the server */
    @XmlElement(name = "serverSupportedKeyExchangeAlgorithm")
    @XmlElementWrapper
    private List<KeyExchangeAlgorithm> serverSupportedKeyExchangeAlgorithms;

    /** List of host key algorithms supported by the client */
    @XmlElement(name = "clientSupportedHostKeyAlgorithm")
    @XmlElementWrapper
    private List<PublicKeyAlgorithm> clientSupportedHostKeyAlgorithms;

    /** List of host key algorithms supported by the server */
    @XmlElement(name = "serverSupportedHostKeyAlgorithm")
    @XmlElementWrapper
    private List<PublicKeyAlgorithm> serverSupportedHostKeyAlgorithms;

    /** List of encryption algorithms (client to server) supported by the client */
    @XmlElement(name = "clientSupportedEncryptionAlgorithmClientToServer")
    @XmlElementWrapper
    private List<EncryptionAlgorithm> clientSupportedEncryptionAlgorithmsClientToServer;

    /** List of encryption algorithms (server to client) supported by the client */
    @XmlElement(name = "clientSupportedEncryptionAlgorithmServerToClient")
    @XmlElementWrapper
    private List<EncryptionAlgorithm> clientSupportedEncryptionAlgorithmsServerToClient;

    /** List of encryption algorithms (client to server) supported by the server */
    @XmlElement(name = "serverSupportedEncryptionAlgorithmServerToClient")
    @XmlElementWrapper
    private List<EncryptionAlgorithm> serverSupportedEncryptionAlgorithmsServerToClient;

    /** List of encryption algorithms (server to client) supported by the server */
    @XmlElement(name = "serverSupportedEncryptionAlgorithmClientToServer")
    @XmlElementWrapper
    private List<EncryptionAlgorithm> serverSupportedEncryptionAlgorithmsClientToServer;

    /** List of MAC algorithms (client to server) supported by the client */
    @XmlElement(name = "clientSupportedMacAlgorithmClientToServer")
    @XmlElementWrapper
    private List<MacAlgorithm> clientSupportedMacAlgorithmsClientToServer;

    /** List of MAC algorithms (server to client) supported by the client */
    @XmlElement(name = "clientSupportedMacAlgorithmServerToClient")
    @XmlElementWrapper
    private List<MacAlgorithm> clientSupportedMacAlgorithmsServerToClient;

    /** List of MAC algorithms (client to server) supported by the server */
    @XmlElement(name = "serverSupportedMacAlgorithmServerToClient")
    @XmlElementWrapper
    private List<MacAlgorithm> serverSupportedMacAlgorithmsServerToClient;

    /** List of MAC algorithms (server to client) supported by the server */
    @XmlElement(name = "serverSupportedMacAlgorithmClientToServer")
    @XmlElementWrapper
    private List<MacAlgorithm> serverSupportedMacAlgorithmsClientToServer;

    /** List of compression algorithms (client to server) supported by the client */
    @XmlElement(name = "clientSupportedCompressionMethodClientToServer")
    @XmlElementWrapper
    private List<CompressionMethod> clientSupportedCompressionMethodsClientToServer;

    /** List of compression algorithms (server to client) supported by the client */
    @XmlElement(name = "clientSupportedCompressionMethodServerToClient")
    @XmlElementWrapper
    private List<CompressionMethod> clientSupportedCompressionMethodsServerToClient;

    /** List of compression algorithms (client to server) supported by the server */
    @XmlElement(name = "serverSupportedCompressionMethodServerToClient")
    @XmlElementWrapper
    private List<CompressionMethod> serverSupportedCompressionMethodsServerToClient;

    /** List of compression algorithms (server to client) supported by the server */
    @XmlElement(name = "serverSupportedCompressionMethodClientToServer")
    @XmlElementWrapper
    private List<CompressionMethod> serverSupportedCompressionMethodsClientToServer;

    /** List of languages (client to server) supported by the client */
    @XmlElement(name = "clientSupportedLanguageClientToServer")
    @XmlElementWrapper
    private List<String> clientSupportedLanguagesClientToServer;

    /** List of languages (server to client) supported by the client */
    @XmlElement(name = "clientSupportedLanguageServerToClient")
    @XmlElementWrapper
    private List<String> clientSupportedLanguagesServerToClient;

    /** List of languages (client to server) supported by the server */
    @XmlElement(name = "serverSupportedLanguageServerToClient")
    @XmlElementWrapper
    private List<String> serverSupportedLanguagesServerToClient;

    /** List of languages (server to client) supported by the server */
    @XmlElement(name = "serverSupportedLanguageClientToServer")
    @XmlElementWrapper
    private List<String> serverSupportedLanguagesClientToServer;

    /**
     * A boolean flag used to indicate that a guessed key exchange paket will be sent by the client
     */
    private boolean clientFirstKeyExchangePacketFollows;

    /**
     * A boolean flag used to indicate that a guessed key exchange paket will be sent by the server
     */
    private boolean serverFirstKeyExchangePacketFollows;

    /** Value of the clients' reserved field which may be used for extensions in the future */
    private int clientReserved;

    /** Value of the servers' reserved field which may be used for extensions in the future */
    private int serverReserved;
    // endregion

    // region KeyExchange
    /**
     * Fallback of minimal acceptable DH group size as reported in the SSH_MSG_KEX_DH_GEX_REQUEST
     * message
     */
    private Integer dhGexMinimalGroupSize;
    /** Fallback of preferred DH group size as reported in the SSH_MSG_KEX_DH_GEX_REQUEST message */
    private Integer dhGexPreferredGroupSize;
    /**
     * Fallback of maximal acceptable DH group size as reported in the SSH_MSG_KEX_DH_GEX_REQUEST
     * message
     */
    private Integer dhGexMaximalGroupSize;
    /**
     * Default DH key exchange algorithm, which is used if a new DH or DH Gex key exchange is
     * instantiated with without a matching key exchange algorithm negotiated.
     */
    private KeyExchangeAlgorithm defaultDhKeyExchangeAlgorithm;
    /**
     * Default ECDH key exchange algorithm, which is used if a new ECDH or X curve ECDH key exchange
     * is instantiated without a matching key exchange algorithm negotiated.
     */
    private KeyExchangeAlgorithm defaultEcdhKeyExchangeAlgorithm;
    /**
     * Default RSA key exchange algorithm, which is used if a new RSA key exchange is instantiated
     * without a matching key exchange algorithm negotiated.
     */
    private KeyExchangeAlgorithm defaultRsaKeyExchangeAlgorithm;
    /**
     * Default Hybrid key exchange algorithm, which is used if a new Hybrid key exchange is
     * instantiaded without a matching key exchange algorithm negotiated.
     */
    private KeyExchangeAlgorithm defaultHybridKeyExchangeAlgorithm;
    /**
     * If set to true, sending or receiving a NewKeysMessage automatically enables the encryption
     * for the corresponding transport direction. If set to false, encryption must be enabled
     * manually by calling the corresponding methods on the state.
     */
    private Boolean enableEncryptionOnNewKeysMessage = true;
    /**
     * If set to false, the packet cipher will only be changed in case of algorithm or key material
     * change during the SSH_MSG_NEWKEYS handler. This can be useful if one tries sending NEWKEYS
     * without a proper key exchange beforehand and would like to be able to decrypt the servers'
     * response encrypted under the old cipher state. Will take no effect if {@link
     * #enableEncryptionOnNewKeysMessage} is set to false.
     */
    private Boolean forcePacketCipherChange = false;
    /**
     * If enforceSettings is true, the algorithms are expected to be already set in the SshContext,
     * when picking the algorithms
     */
    private Boolean enforceSettings = false;

    /** Host key */
    @XmlElement(name = "hostKey")
    @XmlElementWrapper
    private List<SshPublicKey<?, ?>> hostKeys;

    /**
     * RSA transient key used to encrypt the shared secret K. This may be a transient key generated
     * solely for this SSH connection, or it may be re-used for several connections.
     */
    private final SshPublicKey<CustomRsaPublicKey, CustomRsaPrivateKey>
            fallbackRsaTransientPublicKey;
    // endregion

    // region Authentication
    /**
     * The method, which should be used to authenticate to the server as reported in the
     * SSH_MSG_USERAUTH_REQUEST message.
     */
    private AuthenticationMethod authenticationMethod;
    /** The service name defines the service to start after authentication */
    private String serviceName;
    /** The username used for authentication method password */
    private String username;
    /** The password used for authentication method password */
    private String password;
    /** The List of responses used for UserAuthInfoResponseMessage */
    @XmlElement(name = "preConfiguredAuthResponse")
    @XmlElementWrapper
    private List<AuthenticationResponse> preConfiguredAuthResponses;
    /** The List of user keys for public key authentication */
    @XmlElement(name = "userKey")
    @XmlElementWrapper
    private List<SshPublicKey<?, ?>> userKeys;
    // endregion

    // region Channel
    /** Fallback for command of ChannelRequestExecMessage */
    private String channelCommand;
    /** Default channel values including local channel id and window size */
    private ChannelDefaults channelDefaults;
    /**
     * Fallback for the wantReply field of messages extending the SSH_MSG_GLOBAL_REQUEST or
     * SSH_MSG_CHANNEL_REQUEST messages
     */
    private byte replyWanted;
    /**
     * Fallback for variableName of ChannelRequestEnvMessage, to change server-allowed environment
     * variables
     */
    private String defaultVariableName;
    /**
     * Fallback for variableValue of ChannelRequestEnvMessage, to change server-allowed environment
     * variables
     */
    private String defaultVariableValue;
    /**
     * Default value for the ChannelRequestXonXoffMessage, which is used by the server to inform the
     * client, when it can or cannot perform client flow control.
     */
    private byte clientFlowControl;
    /**
     * Default terminal width in pixels, if a pseudo terminal is requested or changed
     * (ChannelRequestPty/ChannelRequestWindowChangeMessage)
     */
    private int defaultTerminalWidthPixels;
    /**
     * Default terminal width in colums, if a pseudo terminal is requested or changed
     * (ChannelRequestPty/ChannelRequestWindowChangeMessage)
     */
    private int defaultTerminalWidthColumns;
    /**
     * Default terminal height in rows, if a pseudo terminal is requested or changed
     * (ChannelRequestPty/ChannelRequestWindowChangeMessage)
     */
    private int defaultTerminalHeightRows;
    /**
     * Default terminal height in pixels, if a pseudo terminal is requested or used
     * (ChannelRequestPty/ChannelRequestWindowChangeMessage)
     */
    private int defaultTerminalHeightPixels;
    /**
     * Default value of TERM environment variable, to specify the terminal handling of a requested
     * pseudo terminal(pty-req)
     */
    private String defaultTermEnvVariable;
    /** Default name of a predefined subsysten, which should be executed on the remote */
    private String defaultSubsystemName;
    /**
     * The default break length, which is requested when a break operation is performed, by sending
     * ChannelRequestBreakMessage
     */
    private int defaultBreakLength;
    // endregion

    // region Workflow settings
    /** The path to load workflow trace from. The workflow trace must be stored in a XML-File. */
    private String workflowInput = null;
    /**
     * The type of workflow trace, that should be executed by the Ssh client or server. The workflow
     * configuration factory uses the type to create the belonging workflow trace.
     */
    private WorkflowTraceType workflowTraceType;
    /**
     * List of filter types, that should be applied on the workflow(or copy) before saving the
     * trace.
     */
    @XmlElement(name = "outputFilter")
    @XmlElementWrapper
    private List<FilterType> outputFilters;
    /** The path to save the workflow trace as output */
    private String workflowOutput = null;
    /**
     * Defines if the output filters should be applied on the workflowTrace or on a fresh workflow
     * trace copy.
     */
    private Boolean applyFiltersInPlace;
    /** Perform some additional steps after filtering, for example restoring user defined values. */
    private Boolean filtersKeepUserSettings = true;
    /** Defines, if the workflow trace should be executed or not */
    private Boolean workflowExecutorShouldOpen = true;
    /** Defines, whether the SSH-Attacker should stop after a disconnect or not */
    private Boolean stopActionsAfterDisconnect = true;
    /** Defines, whether the SSH-Attacker should stop after a IO exception or not */
    private Boolean stopActionsAfterIOException = true;
    /**
     * Defines, if the used connections of the SSH-Attacker should be closed, after executing the
     * workflow
     */
    private Boolean workflowExecutorShouldClose = true;
    /**
     * Defines if the workflow trace should be resetted before saving, by resetting all SshActions.
     */
    private Boolean resetWorkflowtracesBeforeSaving = false;
    // endregion

    // region ReceiveAction
    /**
     * If set to true, SSH-Attacker will not try to continue receiving when all expected messages
     * were received
     */
    private Boolean quickReceive = true;

    /**
     * The maximum number of bytes to receive in a single receive action. Defaults to 2^24 bytes,
     * RFC 4253 requires each SSH implementation to be able to handle binary packets with a length
     * of at least 35000 bytes.
     */
    private Integer receiveMaximumBytes = 16777216;

    /**
     * If set to true, receive actions will stop receiving whenever a DisconnectMessage was received
     */
    private Boolean stopReceivingAfterDisconnect = false;

    // endregion

    /** The path to save the Config as file. */
    private String configOutput = null;

    /** Fallback for type of chooser, to initialize the chooser in the SshContext */
    private ChooserType chooserType = ChooserType.DEFAULT;

    // region Constructors and Initialization
    public Config() {

        defaultClientConnection = new OutboundConnection("client", 65222, "localhost");
        defaultServerConnection = new InboundConnection("server", 65222, "localhost");

        // region VersionExchange initialization
        clientVersion = "SSH-2.0-OpenSSH_9.0";
        clientComment = "";
        serverVersion = clientVersion;
        serverComment = clientComment;
        clientEndOfMessageSequence = "\r\n";
        serverEndOfMessageSequence = "\r\n";
        // endregion

        // region Pre-KeyExchange initialization
        clientCookie = ArrayConverter.hexStringToByteArray("00000000000000000000000000000000");
        serverCookie = ArrayConverter.hexStringToByteArray("00000000000000000000000000000000");

        // Default values for cryptographic parameters are taken from OpenSSH 8.2p1
        clientSupportedKeyExchangeAlgorithms =
                Arrays.stream(
                                new KeyExchangeAlgorithm[] {
                                    KeyExchangeAlgorithm.SNTRUP761_X25519,
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
                        .filter(KeyExchangeAlgorithm::isAvailable)
                        .collect(Collectors.toCollection(LinkedList::new));
        serverSupportedKeyExchangeAlgorithms =
                new LinkedList<>(clientSupportedKeyExchangeAlgorithms);

        // We don't support CERT_V01 or SK (U2F) host keys (yet), only listed for
        // completeness
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
        clientReserved = 0;
        serverReserved = 0;
        // endregion

        // region KeyExchange initialization
        dhGexMinimalGroupSize = 2048;
        dhGexPreferredGroupSize = 4096;
        dhGexMaximalGroupSize = 8192;

        defaultDhKeyExchangeAlgorithm = KeyExchangeAlgorithm.DIFFIE_HELLMAN_GROUP14_SHA256;
        defaultEcdhKeyExchangeAlgorithm = KeyExchangeAlgorithm.ECDH_SHA2_NISTP256;
        defaultRsaKeyExchangeAlgorithm = KeyExchangeAlgorithm.RSA2048_SHA256;
        defaultHybridKeyExchangeAlgorithm = KeyExchangeAlgorithm.SNTRUP761_X25519;

        // An OpenSSL generated 2048 bit RSA keypair is currently being used as the
        // default host key
        // TODO: Load host keys from file to reduce length of Config class
        hostKeys =
                List.of(
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
                                                16))),
                        // SSH enforces the use of 1024 / 160 bit DSA keys as per RFC 4253 Sec. 6.6
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
                                        new BigInteger(
                                                "00B971EBD0321EEC38C15E01FD9C773CCA23E66879", 16),
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
                                        new BigInteger(
                                                "00B971EBD0321EEC38C15E01FD9C773CCA23E66879", 16),
                                        new BigInteger(
                                                "259DC09E04AD1818271F3E676B17A98B6F7B1D08B43B51FAEF06D2C9F921"
                                                        + "0667ED3C14ABEBEE372D1F325C11C0304AE8B9BAC8914619CA05165BAE2B"
                                                        + "E49BAD5DD8ECB8129CDDD2941D6DDF53C7D53A5FB9D88B58F362034CA6A1"
                                                        + "3929D28942D0054FFA4166D3DDDE0B2FE2E4A0342A827DEF6B6FECDB0614"
                                                        + "8ED403D3FC9C4C79",
                                                16),
                                        new BigInteger(
                                                "7C6B4E2B32192EFC09B7CB12D85CBB4141EF7348", 16))),
                        new SshPublicKey<>(
                                PublicKeyFormat.ECDSA_SHA2_NISTP256,
                                new CustomEcPublicKey(
                                        PointFormatter.formatFromByteArray(
                                                NamedEcGroup.SECP256R1,
                                                ArrayConverter.hexStringToByteArray(
                                                        "0492A8D4E6EECBED47D0AACD15D714FB619D6F3941028874B99117CF8EAE"
                                                                + "BBCDF7CC981DE460635590F3AB5AE6F7DF0A12E6E0DE951DEAE3D2C48EC3"
                                                                + "4C237C61E7")),
                                        NamedEcGroup.SECP256R1),
                                new CustomEcPrivateKey(
                                        new BigInteger(
                                                "8DD62AA24F982B18446E3ECC7E50F8EB976610750242BA637C949F4C8FD6A1CF",
                                                16),
                                        NamedEcGroup.SECP256R1)),
                        new SshPublicKey<>(
                                PublicKeyFormat.ECDSA_SHA2_NISTP384,
                                new CustomEcPublicKey(
                                        PointFormatter.formatFromByteArray(
                                                NamedEcGroup.SECP384R1,
                                                ArrayConverter.hexStringToByteArray(
                                                        "04650469DB4E282660E0DCB23197D10EE935BA038B8B62890EB098420211"
                                                                + "C38D5E4E737FF2A0DC53E1B8A55C65B2BD85673EFEEEE9CE4727374D2E2D"
                                                                + "E8EEA6B8AB146245C8627E2346C76944AEB1C0BDCE1B267773F6ED08473A"
                                                                + "DE8B6F5687A2B6")),
                                        NamedEcGroup.SECP384R1),
                                new CustomEcPrivateKey(
                                        new BigInteger(
                                                "EA39EE919D73A1FE8F8FBFC8807E7ED36BE3D89FBC1F35619B04E825E8E8"
                                                        + "07E994348EE8095467499AE15F73FE0FD298",
                                                16),
                                        NamedEcGroup.SECP384R1)),
                        new SshPublicKey<>(
                                PublicKeyFormat.ECDSA_SHA2_NISTP521,
                                new CustomEcPublicKey(
                                        PointFormatter.formatFromByteArray(
                                                NamedEcGroup.SECP521R1,
                                                ArrayConverter.hexStringToByteArray(
                                                        "0400A97EC5412F12C6CCAEDF2F288041146015FBCE1B939F017039D63280"
                                                                + "9B170C1E51B5AFE19127F97146C0556A70E44D179B76DA98C39ACF418F98"
                                                                + "95F7E8483665A800AF936C1864E14340ABE09860281D9A015E0C78A540F1"
                                                                + "6CB36DD0275C9AF61A2A41F6AE6447ECCFCA1788878B7A249B195424BED8"
                                                                + "CD881C0C3C5CEB051D64366DE5")),
                                        NamedEcGroup.SECP521R1),
                                new CustomEcPrivateKey(
                                        new BigInteger(
                                                "015B220911DD64BD8793BC5429093B7AE8E2B4F462751D553CE48E09D72E"
                                                        + "9981F4EF80334B981D6558C6498BFB4B6E1973BF60BF568C624934F1EF2B"
                                                        + "8561C67B2AD2",
                                                16),
                                        NamedEcGroup.SECP521R1)),
                        new SshPublicKey<>(
                                PublicKeyFormat.SSH_ED25519,
                                new XCurveEcPublicKey(
                                        ArrayConverter.hexStringToByteArray(
                                                "13E3591CC0D1BAE515EC44FD3FA01784E2103165ECCFE939D91A619F46DBED70"),
                                        NamedEcGroup.CURVE25519),
                                new XCurveEcPrivateKey(
                                        ArrayConverter.hexStringToByteArray(
                                                "092E829DE536BE8F7D74E7A3C6CD90EA6EADDDEEB2E50D8617EBDD132B53669B"),
                                        NamedEcGroup.CURVE25519)));

        fallbackRsaTransientPublicKey =
                new SshPublicKey<>(
                        PublicKeyFormat.SSH_RSA,
                        new CustomRsaPublicKey(
                                new BigInteger("10001", 16),
                                new BigInteger(
                                        "00EB617D71223FF5D286DBC136905B348783D4B540EFA9E00C7B1F605049"
                                                + "7C6739FBAB3F5D5F2C9A86682D148701E9E04D58D31716C9C88BC0DD85BC"
                                                + "170969A27709AF332C79453FC5B99231C3D6410B0A6119EAEE6D09AB59CF"
                                                + "4EC425BE8A86C10BBA30902B7916D2E51AE5C2CA66E9650431DD3B98878E"
                                                + "EA8A207F4336005157021F7FA4D6DBD54D64B5B974CE3FA4D135C5FD7893"
                                                + "B8A6EAC0C1AC9D98144947C22E7D0E7E18F4F02C0E448D1AE9596BCE0A2E"
                                                + "F417F693C914FAF24F716D0567ED48BAA5161727743A8431EB4E3CB65417"
                                                + "B835926AC528BAA02343B0E784C297E0C19C17FB9E8A778F9EC805AC4AAC"
                                                + "AA24AE34B96A3189D83FB6EC38C1D3EBFB",
                                        16)),
                        new CustomRsaPrivateKey(
                                new BigInteger(
                                        "00C15941BBCF108F1332680D9C8E93FCE05C703BBB6DA33341CD5986BA2C"
                                                + "C31DE04954F025F8EA20BCCB924C4C624C054E43EA920ACC120A8A90ED2C"
                                                + "06185B477354E72FB8169DC5B6DBAAB56A52F2F6E8BDBE9676E7E68B74A8"
                                                + "8FE11BC81AEE7A60F1BEB68E9F571A41CC08742BE2C15193528A924BC6FE"
                                                + "A4B675DF540C65D2697D31E533007B310D7E728D2E6DB06256A93F178200"
                                                + "CED6AD5A59B40224A3373C3875539368971A32D27B48697D4FFE61ED7084"
                                                + "7CA1D935392EA540C938072667BA9C9737A695C20CFCF578A1FF61DD9C43"
                                                + "7666D97D5A986A3E786601498C3342A7C7307F7D8E6300436A7681AA9558"
                                                + "9DF5A4479FAF232B83B9A19CB59833ECC1",
                                        16),
                                new BigInteger(
                                        "00EB617D71223FF5D286DBC136905B348783D4B540EFA9E00C7B1F605049"
                                                + "7C6739FBAB3F5D5F2C9A86682D148701E9E04D58D31716C9C88BC0DD85BC"
                                                + "170969A27709AF332C79453FC5B99231C3D6410B0A6119EAEE6D09AB59CF"
                                                + "4EC425BE8A86C10BBA30902B7916D2E51AE5C2CA66E9650431DD3B98878E"
                                                + "EA8A207F4336005157021F7FA4D6DBD54D64B5B974CE3FA4D135C5FD7893"
                                                + "B8A6EAC0C1AC9D98144947C22E7D0E7E18F4F02C0E448D1AE9596BCE0A2E"
                                                + "F417F693C914FAF24F716D0567ED48BAA5161727743A8431EB4E3CB65417"
                                                + "B835926AC528BAA02343B0E784C297E0C19C17FB9E8A778F9EC805AC4AAC"
                                                + "AA24AE34B96A3189D83FB6EC38C1D3EBFB",
                                        16)));
        // endregion

        // region Authentication initialization
        authenticationMethod = AuthenticationMethod.PASSWORD;
        serviceName = "ssh-userauth";
        username = "sshattacker";
        password = "secret";

        preConfiguredAuthResponses = new LinkedList<>();
        AuthenticationResponse preConfiguredAuthResponse1 = new AuthenticationResponse();
        preConfiguredAuthResponse1.add(new AuthenticationResponse.ResponseEntry(password, false));
        preConfiguredAuthResponses.add(preConfiguredAuthResponse1);
        AuthenticationResponse preConfiguredAuthResponse2 = new AuthenticationResponse();
        preConfiguredAuthResponse2.add(new AuthenticationResponse.ResponseEntry(false));
        preConfiguredAuthResponses.add(preConfiguredAuthResponse2);

        // sshkey generated with "openssl ecparam -name secp521r1 -genkey -out key.pem"
        // pubkey for authorized_keys file on host generated with "ssh-keygen -y -f
        // key.pem >
        // key.pub"
        userKeys =
                List.of(
                        new SshPublicKey<>(
                                PublicKeyFormat.ECDSA_SHA2_NISTP521,
                                new CustomEcPublicKey(
                                        PointFormatter.formatFromByteArray(
                                                NamedEcGroup.SECP521R1,
                                                ArrayConverter.hexStringToByteArray(
                                                        "0400c94546ca3a758e2be7700c6710dbc193db62b511b51c2e5ae09e92"
                                                                + "723527078bfc97d7cfe0b30adec350905d4c3b2f798b88d57ca1a4cc8600ff"
                                                                + "a9568b50b8553400ce85433ffb71641153d690d1c253c8ca395daa9100a547"
                                                                + "f42a0ca8aee4711bcc750294fd6719bb6348d0b92c51d00b7a12ba0646433d"
                                                                + "2f56677b4540ddf89a5da5")),
                                        NamedEcGroup.SECP521R1),
                                new CustomEcPrivateKey(
                                        new BigInteger(
                                                "000bf5ef2fdec03bfa6cf0e2c5ee58c8bcfe0d1b41920792151f2c51b0aa621743b6"
                                                        + "13056155bd51bde866f92b3e9bcfed230381b3dab5100a03c5965538c6f1c30a9",
                                                16),
                                        NamedEcGroup.SECP521R1)));
        // endregion

        // region Channel initialization
        channelDefaults =
                new ChannelDefaults(
                        ChannelType.SESSION,
                        1337,
                        Integer.MAX_VALUE,
                        Integer.MAX_VALUE,
                        0,
                        Integer.MAX_VALUE,
                        35000);
        replyWanted = 0;
        channelCommand = "nc -l -p 13370";
        defaultVariableName = "PATH";
        defaultVariableValue = "usr/local/bin";
        clientFlowControl = 0;
        defaultTerminalWidthColumns = 80;
        defaultTerminalHeightRows = 24;
        defaultTerminalWidthPixels = 640;
        defaultTerminalHeightPixels = 480;
        defaultTermEnvVariable = "vt100";
        defaultSubsystemName = "sftp";
        defaultBreakLength = 600;
        // endregion

        // region Workflow settings initialization
        workflowTraceType = null;
        outputFilters = new ArrayList<>();
        outputFilters.add(FilterType.DEFAULT);
        applyFiltersInPlace = false;
        // endregion
    }
    // endregion

    // region createConfig
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
    // endregion

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

    // region Getters for VersionExchange
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

    // endregion
    // region Setters for VersionExchange
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

    // region Getters for Pre-KeyExchange
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

    // endregion
    // region Setters for Pre-KeyExchange

    public void setClientCookie(byte[] clientCookie) {
        this.clientCookie = clientCookie;
    }

    public void setServerCookie(byte[] serverCookie) {
        this.serverCookie = serverCookie;
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

    // region Getters for KeyExchange
    public Integer getDhGexMinimalGroupSize() {
        return dhGexMinimalGroupSize;
    }

    public Integer getDhGexPreferredGroupSize() {
        return dhGexPreferredGroupSize;
    }

    public Integer getDhGexMaximalGroupSize() {
        return dhGexMaximalGroupSize;
    }

    public KeyExchangeAlgorithm getDefaultDhKeyExchangeAlgorithm() {
        return defaultDhKeyExchangeAlgorithm;
    }

    public KeyExchangeAlgorithm getDefaultEcdhKeyExchangeAlgorithm() {
        return defaultEcdhKeyExchangeAlgorithm;
    }

    public KeyExchangeAlgorithm getDefaultHybridKeyExchangeAlgorithm() {
        return defaultHybridKeyExchangeAlgorithm;
    }

    public KeyExchangeAlgorithm getDefaultRsaKeyExchangeAlgorithm() {
        return defaultRsaKeyExchangeAlgorithm;
    }

    public Boolean getEnableEncryptionOnNewKeysMessage() {
        return enableEncryptionOnNewKeysMessage;
    }

    public Boolean getForcePacketCipherChange() {
        return forcePacketCipherChange;
    }

    public Boolean getEnforceSettings() {
        return enforceSettings;
    }

    public SshPublicKey<CustomRsaPublicKey, CustomRsaPrivateKey>
            getFallbackRsaTransientPublicKey() {
        return fallbackRsaTransientPublicKey;
    }

    public List<SshPublicKey<?, ?>> getHostKeys() {
        return hostKeys;
    }

    // endregion
    // region Setters for KeyExchange
    public void setDhGexMinimalGroupSize(Integer dhGexMinimalGroupSize) {
        this.dhGexMinimalGroupSize = dhGexMinimalGroupSize;
    }

    public void setDhGexPreferredGroupSize(Integer dhGexPreferredGroupSize) {
        this.dhGexPreferredGroupSize = dhGexPreferredGroupSize;
    }

    public void setDhGexMaximalGroupSize(Integer dhGexMaximalGroupSize) {
        this.dhGexMaximalGroupSize = dhGexMaximalGroupSize;
    }

    public void setDefaultDhKeyExchangeAlgorithm(
            KeyExchangeAlgorithm defaultDhKeyExchangeAlgorithm) {
        this.defaultDhKeyExchangeAlgorithm = defaultDhKeyExchangeAlgorithm;
    }

    public void setDefaultHybridKeyExchangeAlgorithm(
            KeyExchangeAlgorithm defaultHybridKeyExchangeAlgorithm) {
        this.defaultHybridKeyExchangeAlgorithm = defaultHybridKeyExchangeAlgorithm;
    }

    public void setDefaultEcdhKeyExchangeAlgorithm(
            KeyExchangeAlgorithm defaultEcdhKeyExchangeAlgorithm) {
        this.defaultEcdhKeyExchangeAlgorithm = defaultEcdhKeyExchangeAlgorithm;
    }

    public void setDefaultRsaKeyExchangeAlgorithm(
            KeyExchangeAlgorithm defaultRsaKeyExchangeAlgorithm) {
        this.defaultRsaKeyExchangeAlgorithm = defaultRsaKeyExchangeAlgorithm;
    }

    public void setEnableEncryptionOnNewKeysMessage(Boolean enableEncryptionOnNewKeysMessage) {
        this.enableEncryptionOnNewKeysMessage = enableEncryptionOnNewKeysMessage;
    }

    public void setForcePacketCipherChange(Boolean forcePacketCipherChange) {
        this.forcePacketCipherChange = forcePacketCipherChange;
    }

    public void setEnforceSettings(Boolean enforceSettings) {
        this.enforceSettings = enforceSettings;
    }

    public void setHostKeys(final List<SshPublicKey<?, ?>> hostKeys) {
        this.hostKeys = Objects.requireNonNull(hostKeys);
    }
    // endregion

    // region Getters for Authentification
    public AuthenticationMethod getAuthenticationMethod() {
        return authenticationMethod;
    }

    public String getUsername() {
        return username;
    }

    public String getPassword() {
        return password;
    }

    public String getServiceName() {
        return serviceName;
    }

    public List<AuthenticationResponse> getPreConfiguredAuthResponses() {
        return preConfiguredAuthResponses;
    }

    public List<SshPublicKey<?, ?>> getUserKeys() {
        return userKeys;
    }

    // endregion
    // region Setters for Authentification
    public void setAuthenticationMethod(AuthenticationMethod authenticationMethod) {
        this.authenticationMethod = authenticationMethod;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public void setPassword(String password) {
        this.password = password;
    }

    public void setServiceName(String serviceName) {
        this.serviceName = serviceName;
    }

    public void setPreConfiguredAuthResponses(
            List<AuthenticationResponse> preConfiguredAuthResponses) {
        this.preConfiguredAuthResponses = preConfiguredAuthResponses;
    }

    public void setUserKeys(final List<SshPublicKey<?, ?>> userKeys) {
        this.userKeys = Objects.requireNonNull(userKeys);
    }

    // endregion

    // region Getters for Channel
    public String getChannelCommand() {
        return channelCommand;
    }

    public byte getReplyWanted() {
        return replyWanted;
    }

    public ChannelDefaults getChannelDefaults() {
        return channelDefaults;
    }

    public String getDefaultVariableValue() {
        return defaultVariableValue;
    }

    public String getDefaultVariableName() {
        return defaultVariableName;
    }

    public byte getClientFlowControl() {
        return clientFlowControl;
    }

    public int getDefaultTerminalWidthPixels() {
        return defaultTerminalWidthPixels;
    }

    public int getDefaultTerminalWidthColumns() {
        return defaultTerminalWidthColumns;
    }

    public int getDefaultTerminalHeightRows() {
        return defaultTerminalHeightRows;
    }

    public int getDefaultTerminalHeightPixels() {
        return defaultTerminalHeightPixels;
    }

    public String getDefaultTermEnvVariable() {
        return defaultTermEnvVariable;
    }

    public String getDefaultSubsystemName() {
        return defaultSubsystemName;
    }

    public int getDefaultBreakLength() {
        return defaultBreakLength;
    }

    // endregion
    // region Setters for Channel
    public void setChannelCommand(String channelCommand) {
        this.channelCommand = channelCommand;
    }

    public void setReplyWanted(byte replyWanted) {
        this.replyWanted = replyWanted;
    }

    public void setChannelDefaults(ChannelDefaults channelDefaults) {
        this.channelDefaults = channelDefaults;
    }

    public void setDefaultVariableValue(String defaultVariableValue) {
        this.defaultVariableValue = defaultVariableValue;
    }

    public void setDefaultVariableName(String defaultVariableName) {
        this.defaultVariableName = defaultVariableName;
    }

    public void setClientFlowControl(byte clientFlowControl) {
        this.clientFlowControl = clientFlowControl;
    }

    public void setDefaultTerminalWidthPixels(int defaultTerminalWidthPixels) {
        this.defaultTerminalWidthPixels = defaultTerminalWidthPixels;
    }

    public void setDefaultTerminalWidthColumns(int defaultTerminalWidthColumns) {
        this.defaultTerminalWidthColumns = defaultTerminalWidthColumns;
    }

    public void setDefaultTerminalHeightRows(int defaultTerminalHeightRows) {
        this.defaultTerminalHeightRows = defaultTerminalHeightRows;
    }

    public void setDefaultTerminalHeightPixels(int defaultTerminalHeightPixels) {
        this.defaultTerminalHeightPixels = defaultTerminalHeightPixels;
    }

    public void setDefaultTermEnvVariable(String defaultTermEnvVariable) {
        this.defaultTermEnvVariable = defaultTermEnvVariable;
    }

    public void setDefaultSubsystemName(String defaultSubsystemName) {
        this.defaultSubsystemName = defaultSubsystemName;
    }

    public void setDefaultBreakLength(int defaultBreakLength) {
        this.defaultBreakLength = defaultBreakLength;
    }

    // endregion

    // region Getters for Workflow settings
    public Boolean isFiltersKeepUserSettings() {
        return filtersKeepUserSettings;
    }

    public String getWorkflowInput() {
        return workflowInput;
    }

    public WorkflowTraceType getWorkflowTraceType() {
        return workflowTraceType;
    }

    public List<FilterType> getOutputFilters() {
        return outputFilters;
    }

    public String getWorkflowOutput() {
        return workflowOutput;
    }

    public Boolean isApplyFiltersInPlace() {
        return applyFiltersInPlace;
    }

    public Boolean getWorkflowExecutorShouldOpen() {
        return workflowExecutorShouldOpen;
    }

    public Boolean getStopActionsAfterDisconnect() {
        return stopActionsAfterDisconnect;
    }

    public Boolean getStopActionsAfterIOException() {
        return stopActionsAfterIOException;
    }

    public Boolean getWorkflowExecutorShouldClose() {
        return workflowExecutorShouldClose;
    }

    public Boolean getResetWorkflowtracesBeforeSaving() {
        return resetWorkflowtracesBeforeSaving;
    }

    // endregion
    // region Setters for Workflow settings

    public void setFiltersKeepUserSettings(Boolean filtersKeepUserSettings) {
        this.filtersKeepUserSettings = filtersKeepUserSettings;
    }

    public void setWorkflowInput(String workflowInput) {
        this.workflowInput = workflowInput;
    }

    public void setWorkflowTraceType(WorkflowTraceType workflowTraceType) {
        this.workflowTraceType = workflowTraceType;
    }

    public void setOutputFilters(List<FilterType> outputFilters) {
        this.outputFilters = outputFilters;
    }

    public void setWorkflowOutput(String workflowOutput) {
        this.workflowOutput = workflowOutput;
    }

    public void setApplyFiltersInPlace(Boolean applyFiltersInPlace) {
        this.applyFiltersInPlace = applyFiltersInPlace;
    }

    public void setWorkflowExecutorShouldOpen(Boolean workflowExecutorShouldOpen) {
        this.workflowExecutorShouldOpen = workflowExecutorShouldOpen;
    }

    public void setStopActionsAfterDisconnect(Boolean stopActionsAfterDisconnect) {
        this.stopActionsAfterDisconnect = stopActionsAfterDisconnect;
    }

    public void setStopActionsAfterIOException(Boolean stopActionsAfterIOException) {
        this.stopActionsAfterIOException = stopActionsAfterIOException;
    }

    public void setWorkflowExecutorShouldClose(Boolean workflowExecutorShouldClose) {
        this.workflowExecutorShouldClose = workflowExecutorShouldClose;
    }

    public void setResetWorkflowtracesBeforeSaving(Boolean resetWorkflowtracesBeforeSaving) {
        this.resetWorkflowtracesBeforeSaving = resetWorkflowtracesBeforeSaving;
    }
    // endregion

    // region Getters for ReceiveAction
    public Boolean isQuickReceive() {
        return quickReceive;
    }

    public Integer getReceiveMaximumBytes() {
        return receiveMaximumBytes;
    }

    public Boolean isStopReceivingAfterDisconnect() {
        return stopReceivingAfterDisconnect;
    }

    // endregion
    // region Setters for ReceiveAction
    public void setQuickReceive(boolean quickReceive) {
        this.quickReceive = quickReceive;
    }

    public void setReceiveMaximumBytes(int receiveMaximumBytes) {
        this.receiveMaximumBytes = receiveMaximumBytes;
    }

    public void setStopReceivingAfterDisconnect(boolean stopReceivingAfterDisconnect) {
        this.stopReceivingAfterDisconnect = stopReceivingAfterDisconnect;
    }
    // endregion

    public String getConfigOutput() {
        return configOutput;
    }

    public void setConfigOutput(String configOutput) {
        this.configOutput = configOutput;
    }

    public ChooserType getChooserType() {
        return chooserType;
    }

    public void setChooserType(ChooserType chooserType) {
        this.chooserType = chooserType;
    }
}
