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
import de.rub.nds.sshattacker.core.crypto.keys.*;
import de.rub.nds.sshattacker.core.protocol.authentication.AuthenticationResponse;
import de.rub.nds.sshattacker.core.protocol.connection.ChannelDefaults;
import de.rub.nds.sshattacker.core.protocol.transport.message.extension.AbstractExtension;
import de.rub.nds.sshattacker.core.protocol.transport.message.extension.DelayCompressionExtension;
import de.rub.nds.sshattacker.core.protocol.transport.message.extension.ServerSigAlgsExtension;
import de.rub.nds.sshattacker.core.util.KeyParser;
import de.rub.nds.sshattacker.core.workflow.action.executor.WorkflowExecutorType;
import de.rub.nds.sshattacker.core.workflow.factory.WorkflowTraceType;
import de.rub.nds.sshattacker.core.workflow.filter.FilterType;
import jakarta.xml.bind.annotation.*;
import jakarta.xml.bind.annotation.adapters.XmlJavaTypeAdapter;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.Serializable;
import java.lang.reflect.Field;
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
     * instantiated without a matching key exchange algorithm negotiated.
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
     * String list of hostkey path, to load default hostkeys. Will be overwritten when parsing paths
     * by CLI
     */
    private List<String> hostKeyPaths;
    /**
     * RSA transient key used to encrypt the shared secret K. This may be a transient key generated
     * solely for this SSH connection, or it may be re-used for several connections.
     */
    private final SshPublicKey<CustomRsaPublicKey, CustomRsaPrivateKey>
            fallbackRsaTransientPublicKey;
    // endregion

    // region SSH Extensions
    /** List of extensions supported by the client */
    private List<AbstractExtension<?>> clientSupportedExtensions;

    /** List of extensions supported by the server */
    private List<AbstractExtension<?>> serverSupportedExtensions;

    /** Flag for enabling and disabling the server-sig-algs extension */
    private boolean respectServerSigAlgsExtension = true;

    /** List of public key algorithms for authentication supported by server */
    private List<PublicKeyAlgorithm> serverSupportedPublicKeyAlgorithmsForAuthentication;

    /** List of compression methods supported by the client(delay-compression extension) */
    private List<CompressionMethod> clientSupportedDelayCompressionMethods;

    /** List of compression methods supported by the server(delay-compression extension) */
    private List<CompressionMethod> serverSupportedDelayCompressionMethods;

    /** Flag for enabling and disabling the delay-compression extension */
    private boolean respectDelayCompressionExtension = true;
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

    /**
     * String list of user keys path, to load default userkeys. Will be overwritten when parsing
     * paths by CLI
     */
    private List<String> userKeyPaths;
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
     * Default terminal width in columns, if a pseudo terminal is requested or changed
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
    /** Default name of a predefined subsystem, which should be executed on the remote */
    private String defaultSubsystemName;
    /**
     * The default break length, which is requested when a break operation is performed, by sending
     * ChannelRequestBreakMessage
     */
    private int defaultBreakLength;
    // endregion

    // region Workflow settings
    /** The path to load workflow trace from. The workflow trace must be stored in an XML-File. */
    private String workflowInput;
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
    private String workflowOutput;
    /** Defines the type of WorkflowExecutor to use when executing the workflow. */
    private WorkflowExecutorType workflowExecutorType = WorkflowExecutorType.DEFAULT;
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
    /** Defines if the workflow trace should be reset before saving, by resetting all SshActions. */
    private Boolean resetWorkflowtracesBeforeSaving = false;
    /**
     * Setting this to true results in the client transport handlers trying to acquire a new port on
     * each connection attempt. Default behavior true so that reused ports are not an issue.
     */
    private Boolean resetClientSourcePort = true;
    /**
     * Setting this to true results in multiple attempts to initialize a connection to the server
     * when a ClientTcpTransportHandler is used.
     */
    private Boolean retryFailedClientTcpSocketInitialization = false;
    /**
     * Setting this to true will stop all further action executions in a workflow trace if an action
     * was not executed as planned.
     */
    private Boolean stopTraceAfterUnexpected = false;
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
    private String configOutput;

    /** Fallback for type of chooser, to initialize the chooser in the SshContext */
    private ChooserType chooserType = ChooserType.DEFAULT;

    // region Constructors and Initialization
    public Config() {
        super();

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
                                    KeyExchangeAlgorithm.SNTRUP4591761_X25519,
                                    KeyExchangeAlgorithm.CURVE25519_SHA256,
                                    KeyExchangeAlgorithm.CURVE25519_SHA256_LIBSSH_ORG,
                                    KeyExchangeAlgorithm.ECDH_SHA2_NISTP256,
                                    KeyExchangeAlgorithm.ECDH_SHA2_NISTP384,
                                    KeyExchangeAlgorithm.ECDH_SHA2_NISTP521,
                                    KeyExchangeAlgorithm.DIFFIE_HELLMAN_GROUP_EXCHANGE_SHA256,
                                    KeyExchangeAlgorithm.DIFFIE_HELLMAN_GROUP16_SHA512,
                                    KeyExchangeAlgorithm.DIFFIE_HELLMAN_GROUP18_SHA512,
                                    KeyExchangeAlgorithm.DIFFIE_HELLMAN_GROUP14_SHA256,
                                    KeyExchangeAlgorithm.EXT_INFO_C
                                })
                        .collect(Collectors.toCollection(LinkedList::new));
        serverSupportedKeyExchangeAlgorithms =
                Arrays.stream(
                                new KeyExchangeAlgorithm[] {
                                    KeyExchangeAlgorithm.SNTRUP761_X25519,
                                    KeyExchangeAlgorithm.SNTRUP4591761_X25519,
                                    KeyExchangeAlgorithm.CURVE25519_SHA256,
                                    KeyExchangeAlgorithm.CURVE25519_SHA256_LIBSSH_ORG,
                                    KeyExchangeAlgorithm.ECDH_SHA2_NISTP256,
                                    KeyExchangeAlgorithm.ECDH_SHA2_NISTP384,
                                    KeyExchangeAlgorithm.ECDH_SHA2_NISTP521,
                                    KeyExchangeAlgorithm.DIFFIE_HELLMAN_GROUP_EXCHANGE_SHA256,
                                    KeyExchangeAlgorithm.DIFFIE_HELLMAN_GROUP16_SHA512,
                                    KeyExchangeAlgorithm.DIFFIE_HELLMAN_GROUP18_SHA512,
                                    KeyExchangeAlgorithm.DIFFIE_HELLMAN_GROUP14_SHA256,
                                    KeyExchangeAlgorithm.EXT_INFO_S
                                })
                        .collect(Collectors.toCollection(LinkedList::new));

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

        // region SSH Extension
        // send delay-compression extension by default when acting as client
        clientSupportedExtensions = new ArrayList<>();
        clientSupportedExtensions.add(new DelayCompressionExtension());

        // send server-sig-algs and delay-compression extension by default when acting as server
        serverSupportedExtensions = new ArrayList<>();
        serverSupportedExtensions.add(new ServerSigAlgsExtension());
        serverSupportedExtensions.add(new DelayCompressionExtension());

        // section server-sig-algs extension
        serverSupportedPublicKeyAlgorithmsForAuthentication =
                Arrays.stream(
                                new PublicKeyAlgorithm[] {
                                    PublicKeyAlgorithm.SSH_DSS,
                                    PublicKeyAlgorithm.SSH_RSA,
                                    PublicKeyAlgorithm.ECDSA_SHA2_NISTP256,
                                    PublicKeyAlgorithm.ECDSA_SHA2_NISTP384,
                                    PublicKeyAlgorithm.ECDSA_SHA2_NISTP521,
                                    PublicKeyAlgorithm.SSH_ED25519
                                })
                        .collect(Collectors.toCollection(LinkedList::new));

        // section delay-compression extension
        clientSupportedDelayCompressionMethods =
                Arrays.stream(
                                new CompressionMethod[] {
                                    CompressionMethod.NONE,
                                    CompressionMethod.ZLIB_OPENSSH_COM,
                                    CompressionMethod.ZLIB
                                })
                        .collect(Collectors.toCollection(LinkedList::new));

        serverSupportedDelayCompressionMethods =
                new LinkedList<>(clientSupportedDelayCompressionMethods);
        // endregion

        // region KeyExchange initialization
        dhGexMinimalGroupSize = 2048;
        dhGexPreferredGroupSize = 4096;
        dhGexMaximalGroupSize = 8192;

        defaultDhKeyExchangeAlgorithm = KeyExchangeAlgorithm.DIFFIE_HELLMAN_GROUP14_SHA256;
        defaultEcdhKeyExchangeAlgorithm = KeyExchangeAlgorithm.ECDH_SHA2_NISTP256;
        defaultRsaKeyExchangeAlgorithm = KeyExchangeAlgorithm.RSA2048_SHA256;
        defaultHybridKeyExchangeAlgorithm = KeyExchangeAlgorithm.SNTRUP761_X25519;
        fallbackRsaTransientPublicKey =
                (SshPublicKey<CustomRsaPublicKey, CustomRsaPrivateKey>)
                        KeyParser.readKeyPairFromBytes(
                                "keys/fallbackkeys/fallbackRsaTransientPublicKey");
        hostKeyPaths =
                List.of(
                        "keys/hostkeys/hostkey_rsa",
                        "keys/hostkeys/hostkey_dsa",
                        "keys/hostkeys/hostkey_ecdsa256",
                        "keys/hostkeys/hostkey_ecdsa384",
                        "keys/hostkeys/hostkey_ecdsa521",
                        "keys/hostkeys/hostkey_ed25519");
        loadHostKeys();
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
        userKeyPaths =
                List.of(
                        "keys/userkeys/id_ecdsa",
                        "keys/userkeys/id_rsa",
                        "keys/userkeys/id_dsa",
                        "keys/userkeys/id_ed25519");
        loadUserKeys();
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

    public static Config createConfig(File file) {
        return ConfigIO.read(file);
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
        Config config = new Config();
        for (Field field : config.getClass().getDeclaredFields()) {
            if (!field.getName().equals("LOGGER") && !field.getType().isPrimitive()) {
                field.setAccessible(true);
                try {
                    field.set(config, null);
                } catch (IllegalAccessException e) {
                    LOGGER.warn("Could not set field in Config!", e);
                }
            }
        }
        return config;
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

    // region Getters SSH Extensions

    // section general extensions
    public List<AbstractExtension<?>> getClientSupportedExtensions() {
        return clientSupportedExtensions;
    }

    public List<AbstractExtension<?>> getServerSupportedExtensions() {
        return serverSupportedExtensions;
    }

    // section server-sig-algs extension
    public List<PublicKeyAlgorithm> getServerSupportedPublicKeyAlgorithmsForAuthentication() {
        return serverSupportedPublicKeyAlgorithmsForAuthentication;
    }

    public boolean getRespectServerSigAlgsExtension() {
        return respectServerSigAlgsExtension;
    }

    // section delay-compression extension
    public List<CompressionMethod> getClientSupportedDelayCompressionMethods() {
        return clientSupportedDelayCompressionMethods;
    }

    public List<CompressionMethod> getServerSupportedDelayCompressionMethods() {
        return serverSupportedDelayCompressionMethods;
    }

    public boolean getRespectDelayCompressionExtension() {
        return respectDelayCompressionExtension;
    }
    // endregion

    // region Setters SSH Extensions

    // section general extensions
    public void setClientSupportedExtensions(List<AbstractExtension<?>> clientSupportedExtensions) {
        this.clientSupportedExtensions = clientSupportedExtensions;
    }

    public void setServerSupportedExtensions(List<AbstractExtension<?>> serverSupportedExtensions) {
        this.serverSupportedExtensions = serverSupportedExtensions;
    }

    // section server-sig-algs extension
    public void setServerSupportedPublicKeyAlgorithmsForAuthentication(
            List<PublicKeyAlgorithm> serverSupportedPublicKeyAlgorithmsForAuthentication) {
        this.serverSupportedPublicKeyAlgorithmsForAuthentication =
                serverSupportedPublicKeyAlgorithmsForAuthentication;
    }

    public void setRespectServerSigAlgsExtension(boolean respectServerSigAlgsExtension) {
        this.respectServerSigAlgsExtension = respectServerSigAlgsExtension;
    }

    // section delay-compression extension
    public void setClientSupportedDelayCompressionMethods(
            List<CompressionMethod> clientSupportedDelayCompressionMethods) {
        this.clientSupportedDelayCompressionMethods = clientSupportedDelayCompressionMethods;
    }

    public void setServerSupportedDelayCompressionMethods(
            List<CompressionMethod> serverSupportedDelayCompressionMethods) {
        this.serverSupportedDelayCompressionMethods = serverSupportedDelayCompressionMethods;
    }

    public void setRespectDelayCompressionExtension(boolean respectDelayCompressionExtension) {
        this.respectDelayCompressionExtension = respectDelayCompressionExtension;
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

    public List<String> getHostKeyPaths() {
        return hostKeyPaths;
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

    public void setHostKeys(List<SshPublicKey<?, ?>> hostKeys) {
        this.hostKeys = Objects.requireNonNull(hostKeys);
    }

    public void setHostKeyPaths(List<String> hostKeyPaths) {
        this.hostKeyPaths = hostKeyPaths;
    }

    // endregion

    // region Getters for authentication
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

    public List<String> getUserKeyPaths() {
        return userKeyPaths;
    }

    // endregion
    // region Setters for authentication
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

    public void setUserKeys(List<SshPublicKey<?, ?>> userKeys) {
        this.userKeys = Objects.requireNonNull(userKeys);
    }

    public void setUserKeyPaths(List<String> userKeyPaths) {
        this.userKeyPaths = userKeyPaths;
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

    public WorkflowExecutorType getWorkflowExecutorType() {
        return workflowExecutorType;
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

    public Boolean getResetClientSourcePort() {
        return resetClientSourcePort;
    }

    public Boolean getRetryFailedClientTcpSocketInitialization() {
        return retryFailedClientTcpSocketInitialization;
    }

    public Boolean getStopTraceAfterUnexpected() {
        return stopTraceAfterUnexpected;
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

    public void setWorkflowExecutorType(WorkflowExecutorType workflowExecutorType) {
        this.workflowExecutorType = workflowExecutorType;
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

    public void setResetClientSourcePort(Boolean resetClientSourcePort) {
        this.resetClientSourcePort = resetClientSourcePort;
    }

    public void setRetryFailedClientTcpSocketInitialization(
            Boolean retryFailedClientTcpSocketInitialization) {
        this.retryFailedClientTcpSocketInitialization = retryFailedClientTcpSocketInitialization;
    }

    public void setStopTraceAfterUnexpected(Boolean stopTraceAfterUnexpected) {
        this.stopTraceAfterUnexpected = stopTraceAfterUnexpected;
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

    public void loadUserKeys() {
        // create a new user key list, because default values will already be written into user keys
        // at time of delegating
        List<SshPublicKey<?, ?>> tempUserKeys = new ArrayList<>();
        SshPublicKey<?, ?> userKey;
        for (String path : userKeyPaths) {
            if ((userKey = KeyParser.readKeyPairFromBytes(path)) != null) {
                tempUserKeys.add(userKey);
            }
        }
        if (!tempUserKeys.isEmpty()) {
            this.setUserKeys(tempUserKeys);
        }
    }

    public void loadHostKeys() {
        // create a new host key list, because default values will already be written into host keys
        // at time of delegating
        List<SshPublicKey<?, ?>> tempHostKeys = new ArrayList<>();
        SshPublicKey<?, ?> hostKey;
        for (String path : hostKeyPaths) {
            if ((hostKey = KeyParser.readKeyPairFromBytes(path)) != null) {
                tempHostKeys.add(hostKey);
            }
        }
        if (!tempHostKeys.isEmpty()) {
            this.setHostKeys(tempHostKeys);
        }
    }

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
