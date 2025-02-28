/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.config;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.modifiablevariable.util.IllegalStringAdapter;
import de.rub.nds.modifiablevariable.util.UnformattedByteArrayAdapter;
import de.rub.nds.sshattacker.core.connection.InboundConnection;
import de.rub.nds.sshattacker.core.connection.OutboundConnection;
import de.rub.nds.sshattacker.core.constants.*;
import de.rub.nds.sshattacker.core.crypto.ec.PointFormatter;
import de.rub.nds.sshattacker.core.crypto.keys.*;
import de.rub.nds.sshattacker.core.data.sftp.common.message.extension.*;
import de.rub.nds.sshattacker.core.protocol.authentication.AuthenticationPromptEntries;
import de.rub.nds.sshattacker.core.protocol.authentication.AuthenticationResponseEntries;
import de.rub.nds.sshattacker.core.protocol.authentication.message.holder.AuthenticationPromptEntry;
import de.rub.nds.sshattacker.core.protocol.authentication.message.holder.AuthenticationResponseEntry;
import de.rub.nds.sshattacker.core.protocol.connection.ChannelDefaults;
import de.rub.nds.sshattacker.core.protocol.transport.message.extension.*;
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
import java.math.BigInteger;
import java.security.Security;
import java.util.*;
import java.util.stream.Collectors;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.pqc.jcajce.provider.BouncyCastlePQCProvider;

@XmlRootElement(name = "config")
@XmlAccessorType(XmlAccessType.FIELD)
public class Config implements Serializable {

    private static final Logger LOGGER = LogManager.getLogger();

    private static final String DEFAULT_CONFIG_FILE = "/default_config.xml";

    private static final ConfigCache DEFAULT_CONFIG_CACHE;

    private static final HashMap<File, ConfigCache> PATH_CONFIG_CACHE = new HashMap<>();

    static {
        DEFAULT_CONFIG_CACHE = new ConfigCache(createConfig());
        Security.addProvider(new BouncyCastleProvider());
        Security.addProvider(new BouncyCastlePQCProvider());
    }

    /** Default Connection to use when running as Client */
    private OutboundConnection defaultClientConnection;

    /** Default Connection to use when running as Server */
    private InboundConnection defaultServerConnection;

    /** The default running mode, when running the SSH-Attacker */
    private RunningModeType defaultRunningMode = RunningModeType.CLIENT;

    // region VersionExchange
    /** Client protocol and software version string starting with the SSH version (SSH-2.0-...) */
    @XmlJavaTypeAdapter(IllegalStringAdapter.class)
    private String clientVersion;

    /** Client comment sent alongside protocol and software version */
    @XmlJavaTypeAdapter(IllegalStringAdapter.class)
    private String clientComment;

    /** End-of-message sequence of the clients' VersionExchangeMessage */
    @XmlJavaTypeAdapter(IllegalStringAdapter.class)
    private String clientEndOfMessageSequence;

    /** Server protocol and software version string starting with the SSH version (SSH-2.0-...) */
    @XmlJavaTypeAdapter(IllegalStringAdapter.class)
    private String serverVersion;

    /** Server comment sent alongside protocol and software version */
    @XmlJavaTypeAdapter(IllegalStringAdapter.class)
    private String serverComment;

    /** End-of-message sequence of the servers' VersionExchangeMessage */
    @XmlJavaTypeAdapter(IllegalStringAdapter.class)
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
    private ArrayList<KeyExchangeAlgorithm> clientSupportedKeyExchangeAlgorithms;

    /** List of key exchange algorithms supported by the server */
    @XmlElement(name = "serverSupportedKeyExchangeAlgorithm")
    @XmlElementWrapper
    private ArrayList<KeyExchangeAlgorithm> serverSupportedKeyExchangeAlgorithms;

    /** List of host key algorithms supported by the client */
    @XmlElement(name = "clientSupportedHostKeyAlgorithm")
    @XmlElementWrapper
    private ArrayList<PublicKeyAlgorithm> clientSupportedHostKeyAlgorithms;

    /** List of host key algorithms supported by the server */
    @XmlElement(name = "serverSupportedHostKeyAlgorithm")
    @XmlElementWrapper
    private ArrayList<PublicKeyAlgorithm> serverSupportedHostKeyAlgorithms;

    /** List of encryption algorithms (client to server) supported by the client */
    @XmlElement(name = "clientSupportedEncryptionAlgorithmClientToServer")
    @XmlElementWrapper
    private ArrayList<EncryptionAlgorithm> clientSupportedEncryptionAlgorithmsClientToServer;

    /** List of encryption algorithms (server to client) supported by the client */
    @XmlElement(name = "clientSupportedEncryptionAlgorithmServerToClient")
    @XmlElementWrapper
    private ArrayList<EncryptionAlgorithm> clientSupportedEncryptionAlgorithmsServerToClient;

    /** List of encryption algorithms (client to server) supported by the server */
    @XmlElement(name = "serverSupportedEncryptionAlgorithmServerToClient")
    @XmlElementWrapper
    private ArrayList<EncryptionAlgorithm> serverSupportedEncryptionAlgorithmsServerToClient;

    /** List of encryption algorithms (server to client) supported by the server */
    @XmlElement(name = "serverSupportedEncryptionAlgorithmClientToServer")
    @XmlElementWrapper
    private ArrayList<EncryptionAlgorithm> serverSupportedEncryptionAlgorithmsClientToServer;

    /** List of MAC algorithms (client to server) supported by the client */
    @XmlElement(name = "clientSupportedMacAlgorithmClientToServer")
    @XmlElementWrapper
    private ArrayList<MacAlgorithm> clientSupportedMacAlgorithmsClientToServer;

    /** List of MAC algorithms (server to client) supported by the client */
    @XmlElement(name = "clientSupportedMacAlgorithmServerToClient")
    @XmlElementWrapper
    private ArrayList<MacAlgorithm> clientSupportedMacAlgorithmsServerToClient;

    /** List of MAC algorithms (client to server) supported by the server */
    @XmlElement(name = "serverSupportedMacAlgorithmServerToClient")
    @XmlElementWrapper
    private ArrayList<MacAlgorithm> serverSupportedMacAlgorithmsServerToClient;

    /** List of MAC algorithms (server to client) supported by the server */
    @XmlElement(name = "serverSupportedMacAlgorithmClientToServer")
    @XmlElementWrapper
    private ArrayList<MacAlgorithm> serverSupportedMacAlgorithmsClientToServer;

    /** List of compression algorithms (client to server) supported by the client */
    @XmlElement(name = "clientSupportedCompressionMethodClientToServer")
    @XmlElementWrapper
    private ArrayList<CompressionMethod> clientSupportedCompressionMethodsClientToServer;

    /** List of compression algorithms (server to client) supported by the client */
    @XmlElement(name = "clientSupportedCompressionMethodServerToClient")
    @XmlElementWrapper
    private ArrayList<CompressionMethod> clientSupportedCompressionMethodsServerToClient;

    /** List of compression algorithms (client to server) supported by the server */
    @XmlElement(name = "serverSupportedCompressionMethodServerToClient")
    @XmlElementWrapper
    private ArrayList<CompressionMethod> serverSupportedCompressionMethodsServerToClient;

    /** List of compression algorithms (server to client) supported by the server */
    @XmlElement(name = "serverSupportedCompressionMethodClientToServer")
    @XmlElementWrapper
    private ArrayList<CompressionMethod> serverSupportedCompressionMethodsClientToServer;

    /** List of languages (client to server) supported by the client */
    @XmlElement(name = "clientSupportedLanguageClientToServer")
    @XmlElementWrapper
    private ArrayList<LanguageTag> clientSupportedLanguagesClientToServer;

    /** List of languages (server to client) supported by the client */
    @XmlElement(name = "clientSupportedLanguageServerToClient")
    @XmlElementWrapper
    private ArrayList<LanguageTag> clientSupportedLanguagesServerToClient;

    /** List of languages (client to server) supported by the server */
    @XmlElement(name = "serverSupportedLanguageServerToClient")
    @XmlElementWrapper
    private ArrayList<LanguageTag> serverSupportedLanguagesServerToClient;

    /** List of languages (server to client) supported by the server */
    @XmlElement(name = "serverSupportedLanguageClientToServer")
    @XmlElementWrapper
    private ArrayList<LanguageTag> serverSupportedLanguagesClientToServer;

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
    // TODO: Would be nice to have an option to reuse ephemeral keys during key exchange.
    // TODO: Would be nice to have an option to disable signature checks
    // TODO: We could replace Integer and Boolean with primitives
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
    private ConnectionDirection enableEncryptionOnNewKeysMessage = ConnectionDirection.BOTH;

    /**
     * If set to false, the packet cipher will only be changed in case of algorithm or key material
     * change during the SSH_MSG_NEWKEYS handler. This can be useful if one tries sending NEWKEYS
     * without a proper key exchange beforehand and would like to be able to decrypt the servers'
     * response encrypted under the old cipher state. Will take no effect if {@link
     * #enableEncryptionOnNewKeysMessage} is set to NONE.
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
    private ArrayList<SshPublicKey<?, ?>> hostKeys;

    /**
     * RSA transient key used to encrypt the shared secret K. This may be a transient key generated
     * solely for this SSH connection, or it may be re-used for several connections.
     */
    private final SshPublicKey<CustomRsaPublicKey, CustomRsaPrivateKey>
            fallbackRsaTransientPublicKey;

    // endregion

    // region SSH Extensions
    /** List of extensions supported by the client */
    @XmlElementWrapper
    @XmlElements({
        @XmlElement(type = DelayCompressionExtension.class, name = "DelayCompressionExtension"),
        @XmlElement(type = NoFlowControlExtension.class, name = "NoFlowControlExtension"),
        @XmlElement(type = PingExtension.class, name = "PingExtension"),
        @XmlElement(
                type = PublicKeyAlgorithmsRoumenPetrovExtension.class,
                name = "PublicKeyAlgorithmsRoumenPetrovExtension"),
        @XmlElement(type = ServerSigAlgsExtension.class, name = "ServerSigAlgsExtension"),
        @XmlElement(type = UnknownExtension.class, name = "UnknownExtension")
    })
    private ArrayList<AbstractExtension<?>> clientSupportedExtensions;

    /** List of extensions supported by the server */
    @XmlElementWrapper
    @XmlElements({
        @XmlElement(type = DelayCompressionExtension.class, name = "DelayCompressionExtension"),
        @XmlElement(type = NoFlowControlExtension.class, name = "NoFlowControlExtension"),
        @XmlElement(type = PingExtension.class, name = "PingExtension"),
        @XmlElement(
                type = PublicKeyAlgorithmsRoumenPetrovExtension.class,
                name = "PublicKeyAlgorithmsRoumenPetrovExtension"),
        @XmlElement(type = ServerSigAlgsExtension.class, name = "ServerSigAlgsExtension"),
        @XmlElement(type = UnknownExtension.class, name = "UnknownExtension")
    })
    private ArrayList<AbstractExtension<?>> serverSupportedExtensions;

    /** Flag for enabling and disabling the server-sig-algs extension */
    private boolean respectServerSigAlgsExtension = true;

    /** List of public key algorithms for authentication supported by server */
    private ArrayList<PublicKeyAlgorithm> serverSupportedPublicKeyAlgorithmsForAuthentication;

    /** List of compression methods supported by the client(delay-compression extension) */
    private ArrayList<CompressionMethod> clientSupportedDelayCompressionMethods;

    /** List of compression methods supported by the server(delay-compression extension) */
    private ArrayList<CompressionMethod> serverSupportedDelayCompressionMethods;

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
    @XmlJavaTypeAdapter(IllegalStringAdapter.class)
    private String serviceName;

    /** The username used for authentication method password */
    @XmlJavaTypeAdapter(IllegalStringAdapter.class)
    private String username;

    /** The password used for authentication method password */
    @XmlJavaTypeAdapter(IllegalStringAdapter.class)
    private String password;

    /** The List of responses used for UserAuthInfoResponseMessage */
    @XmlElementWrapper
    @XmlElement(name = "preConfiguredAuthResponse")
    private ArrayList<AuthenticationResponseEntries> preConfiguredAuthResponses;

    /** The List of prompts used for UserAuthInfoRequestMessage */
    @XmlElementWrapper
    @XmlElement(name = "preConfiguredAuthPrompt")
    private ArrayList<AuthenticationPromptEntries> preConfiguredAuthPrompts;

    /** The List of user keys for public key authentication */
    @XmlElementWrapper
    @XmlElement(name = "userKey")
    private ArrayList<SshPublicKey<?, ?>> userKeys;

    // endregion

    // region Channel
    /** Fallback for command of ChannelRequestExecMessage */
    @XmlJavaTypeAdapter(IllegalStringAdapter.class)
    private String channelCommand;

    /** Default channel values including local channel id and window size */
    private ChannelDefaults channelDefaults;

    /**
     * Whether dynamic actions should be generated to reopen a channel if it was closed.
     *
     * <p>Is currently only implement for Client mode and SFTP subsystem
     */
    private Boolean reopenChannelOnClose = true;

    /**
     * Fallback for the wantReply field of messages extending the SSH_MSG_GLOBAL_REQUEST or
     * SSH_MSG_CHANNEL_REQUEST messages
     */
    private byte replyWanted;

    /**
     * Fallback for variableName of ChannelRequestEnvMessage, to change server-allowed environment
     * variables
     */
    @XmlJavaTypeAdapter(IllegalStringAdapter.class)
    private String defaultVariableName;

    /**
     * Fallback for variableValue of ChannelRequestEnvMessage, to change server-allowed environment
     * variables
     */
    @XmlJavaTypeAdapter(IllegalStringAdapter.class)
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
    @XmlJavaTypeAdapter(IllegalStringAdapter.class)
    private String defaultTermEnvVariable;

    /** Default name of a predefined subsystem, which should be executed on the remote */
    @XmlJavaTypeAdapter(IllegalStringAdapter.class)
    private String defaultSubsystemName;

    /**
     * The default break length, which is requested when a break operation is performed, by sending
     * ChannelRequestBreakMessage
     */
    private int defaultBreakLength;

    // endregion

    // region general SSH settings
    // TODO: Think about an option that reflects the modifications on the key exchange messages back
    //  to the context (including ExchangeHashInputHolder), so that the actually modified keys are
    //  used in the computations. Would maybe be interesting for fuzzing

    /**
     * Whether decryption should be omitted if an error occurs during the decryption of a packet.
     * Otherwise, the packet is not parsed any further
     */
    private Boolean fallbackToNoDecryptionOnError;

    /**
     * Whether decompression should be omitted if an error occurs during the decompression of a
     * packet. Otherwise, the packet is not parsed any further.
     */
    private Boolean fallbackToNoDecompressionOnError;

    // endregion

    // region SFTP Version Exchange
    /** SFTP Client protocol version */
    private Integer sftpClientVersion;

    /** SFTP Server protocol version */
    private Integer sftpServerVersion;

    /** SFTP negotiated protocol version */
    private Integer sftpNegotiatedVersion;

    // endregion

    // region SSH Extensions
    /** List of SFTP extensions supported by the client */
    @XmlElementWrapper
    @XmlElements({
        @XmlElement(type = SftpExtensionCheckFile.class, name = "SftpExtensionCheckFile"),
        @XmlElement(type = SftpExtensionCopyData.class, name = "SftpExtensionCopyData"),
        @XmlElement(type = SftpExtensionCopyFile.class, name = "SftpExtensionCopyFile"),
        @XmlElement(type = SftpExtensionExpandPath.class, name = "SftpExtensionExpandPath"),
        @XmlElement(type = SftpExtensionFileStatVfs.class, name = "SftpExtensionFileStatVfs"),
        @XmlElement(type = SftpExtensionFileSync.class, name = "SftpExtensionFileSync"),
        @XmlElement(type = SftpExtensionGetTempFolder.class, name = "SftpExtensionGetTempFolder"),
        @XmlElement(type = SftpExtensionHardlink.class, name = "SftpExtensionHardlink"),
        @XmlElement(type = SftpExtensionHomeDirectory.class, name = "SftpExtensionHomeDirectory"),
        @XmlElement(type = SftpExtensionLimits.class, name = "SftpExtensionLimits"),
        @XmlElement(type = SftpExtensionLinkSetStat.class, name = "SftpExtensionLinkSetStat"),
        @XmlElement(type = SftpExtensionMakeTempFolder.class, name = "SftpExtensionMakeTempFolder"),
        @XmlElement(type = SftpExtensionNewline.class, name = "SftpExtensionNewline"),
        @XmlElement(type = SftpExtensionPosixRename.class, name = "SftpExtensionPosixRename"),
        @XmlElement(type = SftpExtensionSpaceAvailable.class, name = "SftpExtensionSpaceAvailable"),
        @XmlElement(type = SftpExtensionStatVfs.class, name = "SftpExtensionStatVfs"),
        @XmlElement(type = SftpExtensionTextSeek.class, name = "SftpExtensionTextSeek"),
        @XmlElement(type = SftpExtensionUnknown.class, name = "SftpExtensionUnknown"),
        @XmlElement(
                type = SftpExtensionUsersGroupsById.class,
                name = "SftpExtensionUsersGroupsById"),
        @XmlElement(type = SftpExtensionVendorId.class, name = "SftpExtensionVendorId"),
        @XmlElement(type = SftpExtensionWithVersion.class, name = "SftpExtensionWithVersion")
    })
    private ArrayList<SftpAbstractExtension<?>> sftpClientSupportedExtensions;

    /** List of SFTP extensions supported by the server */
    @XmlElementWrapper
    @XmlElements({
        @XmlElement(type = SftpExtensionCheckFile.class, name = "SftpExtensionCheckFile"),
        @XmlElement(type = SftpExtensionCopyData.class, name = "SftpExtensionCopyData"),
        @XmlElement(type = SftpExtensionCopyFile.class, name = "SftpExtensionCopyFile"),
        @XmlElement(type = SftpExtensionExpandPath.class, name = "SftpExtensionExpandPath"),
        @XmlElement(type = SftpExtensionFileStatVfs.class, name = "SftpExtensionFileStatVfs"),
        @XmlElement(type = SftpExtensionFileSync.class, name = "SftpExtensionFileSync"),
        @XmlElement(type = SftpExtensionGetTempFolder.class, name = "SftpExtensionGetTempFolder"),
        @XmlElement(type = SftpExtensionHardlink.class, name = "SftpExtensionHardlink"),
        @XmlElement(type = SftpExtensionHomeDirectory.class, name = "SftpExtensionHomeDirectory"),
        @XmlElement(type = SftpExtensionLimits.class, name = "SftpExtensionLimits"),
        @XmlElement(type = SftpExtensionLinkSetStat.class, name = "SftpExtensionLinkSetStat"),
        @XmlElement(type = SftpExtensionMakeTempFolder.class, name = "SftpExtensionMakeTempFolder"),
        @XmlElement(type = SftpExtensionNewline.class, name = "SftpExtensionNewline"),
        @XmlElement(type = SftpExtensionPosixRename.class, name = "SftpExtensionPosixRename"),
        @XmlElement(type = SftpExtensionSpaceAvailable.class, name = "SftpExtensionSpaceAvailable"),
        @XmlElement(type = SftpExtensionStatVfs.class, name = "SftpExtensionStatVfs"),
        @XmlElement(type = SftpExtensionTextSeek.class, name = "SftpExtensionTextSeek"),
        @XmlElement(type = SftpExtensionUnknown.class, name = "SftpExtensionUnknown"),
        @XmlElement(
                type = SftpExtensionUsersGroupsById.class,
                name = "SftpExtensionUsersGroupsById"),
        @XmlElement(type = SftpExtensionVendorId.class, name = "SftpExtensionVendorId"),
        @XmlElement(type = SftpExtensionWithVersion.class, name = "SftpExtensionWithVersion")
    })
    private ArrayList<SftpAbstractExtension<?>> sftpServerSupportedExtensions;

    // endregion

    // region general SFTP settings
    /** Whether the attributes in messages should be consistent with the attributes flags. */
    private Boolean respectSftpAttributesFlags;

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
    private ArrayList<FilterType> outputFilters;

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

    /**
     * Defines, whether the SSH attacker should treat a timeout when receiving messages like an IO
     * Exception. or not. TODO: This actually also includes real IO Exceptions. Changes must be done
     * to the TransportHandler
     */
    private Boolean handleTimeoutOnReceiveAsIOException = false;

    /** Defines, whether the SSH-Attacker should stop after a IO exception or not */
    private Boolean stopActionsAfterIOException = true;

    /**
     * Defines, if the used connections of the SSH-Attacker should be closed, after executing the
     * workflow
     */
    private Boolean workflowExecutorShouldClose = true;

    /**
     * Defines if the workflow trace should be reset before executing, by resetting all SshActions.
     */
    private Boolean resetWorkflowTraceBeforeExecution = true;

    /** Defines if the workflow trace should be reset before saving, by resetting all SshActions. */
    private Boolean resetWorkflowTraceBeforeSaving = false;

    /**
     * Defines whether the original values of all modifiable variables in the workflow trace should
     * be reset to null when the workflow trace is reset.
     */
    private Boolean resetModifiableVariables = true;

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

    private Boolean allowDynamicGenerationOfActions = true;

    /**
     * Setting this to true will add dynamically generated Actions to the workflow trace. Warning:
     * This can prevent successful re-execution of a workflow trace
     */
    private Boolean addDynamicallyGeneratedActionsToWorkflowTrace = false;

    // endregion

    // region ReceiveAction
    /**
     * If set to true, SSH-Attacker will not try to continue receiving when all expected messages
     * were received. If false and messages are expected, SSH-Attacker will try to continue
     * receiving as long as the socket does not time out.
     */
    private Boolean quickReceive = true;

    /**
     * If set to true, SSH-Attacker will not try to continue receiving when at least one message was
     * received and no messages are expected. If false and no messages are expected, SSH-Attacker
     * will try to continue receiving as long as the socket does not time out.
     */
    private Boolean endReceivingEarly = false;

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

        // Default values for cryptographic parameters are taken from OpenSSH 9.9p1
        clientSupportedKeyExchangeAlgorithms =
                Arrays.stream(
                                new KeyExchangeAlgorithm[] {
                                    KeyExchangeAlgorithm.SNTRUP761X25519_SHA512,
                                    KeyExchangeAlgorithm.SNTRUP761X25519_SHA512_OPENSSH_COM,
                                    KeyExchangeAlgorithm.MLKEM768X25519_SHA256,
                                    KeyExchangeAlgorithm.CURVE25519_SHA256,
                                    KeyExchangeAlgorithm.CURVE25519_SHA256_LIBSSH_ORG,
                                    KeyExchangeAlgorithm.ECDH_SHA2_NISTP256,
                                    KeyExchangeAlgorithm.ECDH_SHA2_NISTP384,
                                    KeyExchangeAlgorithm.ECDH_SHA2_NISTP521,
                                    KeyExchangeAlgorithm.DIFFIE_HELLMAN_GROUP_EXCHANGE_SHA256,
                                    KeyExchangeAlgorithm.DIFFIE_HELLMAN_GROUP16_SHA512,
                                    KeyExchangeAlgorithm.DIFFIE_HELLMAN_GROUP18_SHA512,
                                    KeyExchangeAlgorithm.DIFFIE_HELLMAN_GROUP14_SHA256,
                                    KeyExchangeAlgorithm.EXT_INFO_C,
                                    KeyExchangeAlgorithm.KEX_STRICT_C_V00_OPENSSH_COM
                                })
                        .collect(Collectors.toCollection(ArrayList::new));
        serverSupportedKeyExchangeAlgorithms =
                Arrays.stream(
                                new KeyExchangeAlgorithm[] {
                                    KeyExchangeAlgorithm.SNTRUP761X25519_SHA512,
                                    KeyExchangeAlgorithm.SNTRUP761X25519_SHA512_OPENSSH_COM,
                                    KeyExchangeAlgorithm.MLKEM768X25519_SHA256,
                                    KeyExchangeAlgorithm.CURVE25519_SHA256,
                                    KeyExchangeAlgorithm.CURVE25519_SHA256_LIBSSH_ORG,
                                    KeyExchangeAlgorithm.ECDH_SHA2_NISTP256,
                                    KeyExchangeAlgorithm.ECDH_SHA2_NISTP384,
                                    KeyExchangeAlgorithm.ECDH_SHA2_NISTP521,
                                    KeyExchangeAlgorithm.DIFFIE_HELLMAN_GROUP_EXCHANGE_SHA256,
                                    KeyExchangeAlgorithm.DIFFIE_HELLMAN_GROUP16_SHA512,
                                    KeyExchangeAlgorithm.DIFFIE_HELLMAN_GROUP18_SHA512,
                                    KeyExchangeAlgorithm.DIFFIE_HELLMAN_GROUP14_SHA256,
                                    KeyExchangeAlgorithm.EXT_INFO_S,
                                    KeyExchangeAlgorithm.KEX_STRICT_S_V00_OPENSSH_COM
                                })
                        .collect(Collectors.toCollection(ArrayList::new));

        // We don't support SK (U2F) host keys (yet), only listed for
        // completeness
        clientSupportedHostKeyAlgorithms =
                Arrays.stream(
                                new PublicKeyAlgorithm[] {
                                    PublicKeyAlgorithm.ECDSA_SHA2_NISTP256_CERT_V01_OPENSSH_COM,
                                    PublicKeyAlgorithm.ECDSA_SHA2_NISTP384_CERT_V01_OPENSSH_COM,
                                    PublicKeyAlgorithm.ECDSA_SHA2_NISTP521_CERT_V01_OPENSSH_COM,
                                    // PublicKeyAlgorithm.SK_ECDSA_SHA2_NISTP256_CERT_V01_OPENSSH_COM,
                                    PublicKeyAlgorithm.SSH_ED25519_CERT_V01_OPENSSH_COM,
                                    // PublicKeyAlgorithm.SK_SSH_ED25519_CERT_V01_OPENSSH_COM,
                                    PublicKeyAlgorithm.RSA_SHA2_512_CERT_V01_OPENSSH_COM,
                                    PublicKeyAlgorithm.RSA_SHA2_256_CERT_V01_OPENSSH_COM,
                                    PublicKeyAlgorithm.SSH_RSA_CERT_V01_OPENSSH_COM,
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
                        .collect(Collectors.toCollection(ArrayList::new));
        serverSupportedHostKeyAlgorithms = new ArrayList<>(clientSupportedHostKeyAlgorithms);

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
                        .collect(Collectors.toCollection(ArrayList::new));
        clientSupportedEncryptionAlgorithmsServerToClient =
                new ArrayList<>(clientSupportedEncryptionAlgorithmsClientToServer);
        serverSupportedEncryptionAlgorithmsClientToServer =
                new ArrayList<>(clientSupportedEncryptionAlgorithmsClientToServer);
        serverSupportedEncryptionAlgorithmsServerToClient =
                new ArrayList<>(clientSupportedEncryptionAlgorithmsClientToServer);

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
                        .collect(Collectors.toCollection(ArrayList::new));
        clientSupportedMacAlgorithmsServerToClient =
                new ArrayList<>(clientSupportedMacAlgorithmsClientToServer);
        serverSupportedMacAlgorithmsServerToClient =
                new ArrayList<>(clientSupportedMacAlgorithmsClientToServer);
        serverSupportedMacAlgorithmsClientToServer =
                new ArrayList<>(clientSupportedMacAlgorithmsClientToServer);

        clientSupportedCompressionMethodsClientToServer =
                Arrays.stream(
                                new CompressionMethod[] {
                                    CompressionMethod.NONE,
                                    CompressionMethod.ZLIB_OPENSSH_COM,
                                    CompressionMethod.ZLIB
                                })
                        .collect(Collectors.toCollection(ArrayList::new));
        clientSupportedCompressionMethodsServerToClient =
                new ArrayList<>(clientSupportedCompressionMethodsClientToServer);
        serverSupportedCompressionMethodsServerToClient =
                new ArrayList<>(clientSupportedCompressionMethodsClientToServer);
        serverSupportedCompressionMethodsClientToServer =
                new ArrayList<>(clientSupportedCompressionMethodsClientToServer);

        clientSupportedLanguagesClientToServer = new ArrayList<>();
        clientSupportedLanguagesServerToClient =
                new ArrayList<>(clientSupportedLanguagesClientToServer);
        serverSupportedLanguagesServerToClient =
                new ArrayList<>(clientSupportedLanguagesClientToServer);
        serverSupportedLanguagesClientToServer =
                new ArrayList<>(clientSupportedLanguagesClientToServer);

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
                        .collect(Collectors.toCollection(ArrayList::new));

        // section delay-compression extension
        clientSupportedDelayCompressionMethods =
                Arrays.stream(
                                new CompressionMethod[] {
                                    CompressionMethod.NONE,
                                    CompressionMethod.ZLIB_OPENSSH_COM,
                                    CompressionMethod.ZLIB
                                })
                        .collect(Collectors.toCollection(ArrayList::new));

        serverSupportedDelayCompressionMethods =
                new ArrayList<>(clientSupportedDelayCompressionMethods);
        // endregion

        // region KeyExchange initialization
        dhGexMinimalGroupSize = 2048;
        dhGexPreferredGroupSize = 4096;
        dhGexMaximalGroupSize = 8192;

        defaultDhKeyExchangeAlgorithm = KeyExchangeAlgorithm.DIFFIE_HELLMAN_GROUP14_SHA256;
        defaultEcdhKeyExchangeAlgorithm = KeyExchangeAlgorithm.ECDH_SHA2_NISTP256;
        defaultRsaKeyExchangeAlgorithm = KeyExchangeAlgorithm.RSA2048_SHA256;
        defaultHybridKeyExchangeAlgorithm = KeyExchangeAlgorithm.SNTRUP761X25519_SHA512;

        // An OpenSSL generated 2048 bit RSA keypair is currently being used as the
        // default host key
        // TODO: Load host keys from file to reduce length of Config class
        hostKeys =
                new ArrayList<>(
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
                                // SSH enforces the use of 1024 / 160 bit DSA keys as per RFC 4253
                                // Sec. 6.6
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
                                                        "00B971EBD0321EEC38C15E01FD9C773CCA23E66879",
                                                        16),
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
                                                        "00B971EBD0321EEC38C15E01FD9C773CCA23E66879",
                                                        16),
                                                new BigInteger(
                                                        "259DC09E04AD1818271F3E676B17A98B6F7B1D08B43B51FAEF06D2C9F921"
                                                                + "0667ED3C14ABEBEE372D1F325C11C0304AE8B9BAC8914619CA05165BAE2B"
                                                                + "E49BAD5DD8ECB8129CDDD2941D6DDF53C7D53A5FB9D88B58F362034CA6A1"
                                                                + "3929D28942D0054FFA4166D3DDDE0B2FE2E4A0342A827DEF6B6FECDB0614"
                                                                + "8ED403D3FC9C4C79",
                                                        16),
                                                new BigInteger(
                                                        "7C6B4E2B32192EFC09B7CB12D85CBB4141EF7348",
                                                        16))),
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
                                                NamedEcGroup.CURVE25519))));

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

        preConfiguredAuthResponses = new ArrayList<>();

        ArrayList<AuthenticationResponseEntry> preConfiguredAuthResponse1 = new ArrayList<>();
        preConfiguredAuthResponse1.add(new AuthenticationResponseEntry());
        preConfiguredAuthResponses.add(
                new AuthenticationResponseEntries(preConfiguredAuthResponse1));
        ArrayList<AuthenticationResponseEntry> preConfiguredAuthResponse2 = new ArrayList<>();
        preConfiguredAuthResponse2.add(new AuthenticationResponseEntry());
        preConfiguredAuthResponses.add(
                new AuthenticationResponseEntries(preConfiguredAuthResponse2));

        preConfiguredAuthPrompts = new ArrayList<>();
        ArrayList<AuthenticationPromptEntry> preConfiguredAuthPrompt1 = new ArrayList<>();
        preConfiguredAuthPrompt1.add(new AuthenticationPromptEntry());
        preConfiguredAuthPrompts.add(new AuthenticationPromptEntries(preConfiguredAuthPrompt1));

        // sshkey generated with "openssl ecparam -name secp521r1 -genkey -out key.pem"
        // pubkey for authorized_keys file on host generated with "ssh-keygen -y -f
        // key.pem >
        // key.pub"
        userKeys =
                new ArrayList<>(
                        List.of(
                                new SshPublicKey<>(
                                        PublicKeyFormat.SSH_RSA,
                                        new CustomRsaPublicKey(
                                                new BigInteger("10001", 16),
                                                new BigInteger(
                                                        "009df0c70638448afef5799bc7c161d5bc286baeb8a4dc70ffefb2f4813a"
                                                                + "810747d3cbfcd1c9a9ce76272731ed1e2c0ba64feb9af634ae8e4df699b2"
                                                                + "d3b52af4df616ca8003502e38b81bfa6801148c7bab1870a694b44d82ff0"
                                                                + "98633edb09bfbab52b3e7498ce1826813da010000f7c458877f859f46442"
                                                                + "0853220d632d9d1fc113e885e631f15dfcf1fddba90c0c5aa520bc6a55a5"
                                                                + "6a1b29ead5492f83fe7e6b9494afbe16615daa446c2909c218dcd750ae4a"
                                                                + "9a9c69c74d748e904ba8e2ce2812d1ce3c4ed12fd82cca7fe81f88823907"
                                                                + "6702656ef1d3f93e472aae509a0ae5e241c4fd9b661f4cc6ffb02d416a72"
                                                                + "5469e51e27204b3db3f28961e244a9e6c3",
                                                        16)),
                                        new CustomRsaPrivateKey(
                                                new BigInteger(
                                                        "008701ebcef848371c8c0f40c77719bf4f50aa03b7984d4b56abba286152"
                                                                + "f63a97fe86ef7d10ca534f1256e1c99432085f490fd7edbfc8baa2103aff"
                                                                + "ef127d3ec6b80bde6c16e47a47a54882f614504752e22fd20981aabeb5f4"
                                                                + "0eff3f1a9371ce12d17d58c3c9e04101d700bccca070152bfb8952b3a304"
                                                                + "0303b5270671564f6e2753e05e413931e22a6b115fd3264fd6e4c25cb901"
                                                                + "ccdd006d9b5785379f7cbcc1bbd149afda6b51fe13430fb5ca19da594afc"
                                                                + "cd2bd99473001e995033116d48d329d42255ef0eec11a6d2310eb97912d7"
                                                                + "19b7b75d74696613e21305da6715846bf04c4e76046fbf86a793d96c0fe7"
                                                                + "02638696eed4b7488c18233db879e70149",
                                                        16),
                                                new BigInteger(
                                                        "009df0c70638448afef5799bc7c161d5bc286baeb8a4dc70ffefb2f4813a"
                                                                + "810747d3cbfcd1c9a9ce76272731ed1e2c0ba64feb9af634ae8e4df699b2"
                                                                + "d3b52af4df616ca8003502e38b81bfa6801148c7bab1870a694b44d82ff0"
                                                                + "98633edb09bfbab52b3e7498ce1826813da010000f7c458877f859f46442"
                                                                + "0853220d632d9d1fc113e885e631f15dfcf1fddba90c0c5aa520bc6a55a5"
                                                                + "6a1b29ead5492f83fe7e6b9494afbe16615daa446c2909c218dcd750ae4a"
                                                                + "9a9c69c74d748e904ba8e2ce2812d1ce3c4ed12fd82cca7fe81f88823907"
                                                                + "6702656ef1d3f93e472aae509a0ae5e241c4fd9b661f4cc6ffb02d416a72"
                                                                + "5469e51e27204b3db3f28961e244a9e6c3",
                                                        16))),
                                new SshPublicKey<>(
                                        PublicKeyFormat.ECDSA_SHA2_NISTP521,
                                        new CustomEcPublicKey(
                                                PointFormatter.formatFromByteArray(
                                                        NamedEcGroup.SECP521R1,
                                                        ArrayConverter.hexStringToByteArray(
                                                                "0400c94546ca3a758e2be7700c6710dbc193db62b511b51c"
                                                                        + "2e5ae09e92723527078bfc97d7cfe0b30adec350905d4c3b"
                                                                        + "2f798b88d57ca1a4cc8600ffa9568b50b8553400ce85433f"
                                                                        + "fb71641153d690d1c253c8ca395daa9100a547f42a0ca8ae"
                                                                        + "e4711bcc750294fd6719bb6348d0b92c51d00b7a12ba0646"
                                                                        + "433d2f56677b4540ddf89a5da5")),
                                                NamedEcGroup.SECP521R1),
                                        new CustomEcPrivateKey(
                                                new BigInteger(
                                                        "000bf5ef2fdec03bfa6cf0e2c5ee58c8bcfe0d1b41920792151f2c"
                                                                + "51b0aa621743b613056155bd51bde866f92b3e9bcfed230381"
                                                                + "b3dab5100a03c5965538c6f1c30a9",
                                                        16),
                                                NamedEcGroup.SECP521R1)),
                                new SshPublicKey<>(
                                        PublicKeyFormat.SSH_ED25519,
                                        new XCurveEcPublicKey(
                                                ArrayConverter.hexStringToByteArray(
                                                        "99AF546D30DD1770CC27A1A1CE7AD1CEC729823527529352141E89F7F3420F2C"),
                                                NamedEcGroup.CURVE25519),
                                        new XCurveEcPrivateKey(
                                                ArrayConverter.hexStringToByteArray(
                                                        "6D3703876ED02075102F767E2EA969E311B7776F71630B7C1DF3E55C98D6641B"),
                                                NamedEcGroup.CURVE25519)),
                                new SshPublicKey<>(
                                        PublicKeyFormat.SSH_DSS,
                                        new CustomDsaPublicKey(
                                                new BigInteger(
                                                        "00D34ED25D35236E5A3EFCAE34C30F06F444D1FBE85DC29D71DAD5"
                                                                + "A8EFD5ED45609F4E29484DF5E21DB9926664296EF910AA9822FECDD"
                                                                + "97514479DC28C69AB424A12D792E3B38D56C2DE668DA788286E5136"
                                                                + "8AC1B837C7C928B5B5A6A277ECEA9436FAF7CBF279CD103695B7AEC"
                                                                + "96B4EF975A218483BB715FE0CFEE7BE9E07DFA5",
                                                        16),
                                                new BigInteger(
                                                        "00D8F3DAC6BFAA2CEAFCBF0E249DD0750913A5BFE9",
                                                        16),
                                                new BigInteger(
                                                        "42B4D9C983941ADFDA0E6D9C4583F6FA96417017B389D750CFD717C"
                                                                + "591FD12931167D12C96E3345E79B6225360485FF2E839CA9C38"
                                                                + "D443A4AE2F13D6593FF69605866AC4AD1CD677441FD0D6ED15F"
                                                                + "F636D8231130CC07B8AA6F1DF54A6517983695E3E5FFA3BFF9A"
                                                                + "30B44423D8504CF0748AF99CA79B6A8599759E7C6DBBB5DC",
                                                        16),
                                                new BigInteger(
                                                        "68801435B2A260F778520BD23C9EBF38AF523CB81D64C56F8741890B"
                                                                + "1206CA2E175EE94BFF2C84601F357FB5B6071AB2240D7258D1EDE3D8B"
                                                                + "CC2F6E78DEA5DCBB5BC315B858A1DD833607E0433CDE2FD24240DD2D1"
                                                                + "C45F9508FBA25DC8E6F40D9BC58B6D3246865027E9B5E48F410E084B5"
                                                                + "2A1AE99D2966543243764436757F6",
                                                        16)),
                                        new CustomDsaPrivateKey(
                                                new BigInteger(
                                                        "00D34ED25D35236E5A3EFCAE34C30F06F444D1FBE85DC29D71DAD5A8EFD5"
                                                                + "ED45609F4E29484DF5E21DB9926664296EF910AA9822FECDD97514479D"
                                                                + "C28C69AB424A12D792E3B38D56C2DE668DA788286E51368AC1B837C7C9"
                                                                + "28B5B5A6A277ECEA9436FAF7CBF279CD103695B7AEC96B4EF975A21848"
                                                                + "3BB715FE0CFEE7BE9E07DFA5",
                                                        16),
                                                new BigInteger(
                                                        "00D8F3DAC6BFAA2CEAFCBF0E249DD0750913A5BFE9",
                                                        16),
                                                new BigInteger(
                                                        "42B4D9C983941ADFDA0E6D9C4583F6FA96417017B389D750CFD717C591FD"
                                                                + "12931167D12C96E3345E79B6225360485FF2E839CA9C38D443A4AE2F13D6"
                                                                + "593FF69605866AC4AD1CD677441FD0D6ED15FF636D8231130CC07B8AA6F1"
                                                                + "DF54A6517983695E3E5FFA3BFF9A30B44423D8504CF0748AF99CA79B6A85"
                                                                + "99759E7C6DBBB5DC",
                                                        16),
                                                new BigInteger(
                                                        "6616556442F6B8F1EA8B5FA3A93BB638D55737D8",
                                                        16)))));
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

        // region general SSH Settings
        fallbackToNoDecryptionOnError = true;
        fallbackToNoDecompressionOnError = true;
        // endregion

        // region Workflow settings initialization
        workflowTraceType = null;
        outputFilters = new ArrayList<>();
        outputFilters.add(FilterType.DEFAULT);
        applyFiltersInPlace = false;
        // endregion

        // region SFTP Version Exchange initialization
        sftpClientVersion = 3;
        sftpServerVersion = 3;
        sftpNegotiatedVersion = 4;
        // endregion

        // region SFTP Extension
        sftpClientSupportedExtensions = new ArrayList<>();
        addAllSftpExtensions(sftpClientSupportedExtensions);
        sftpServerSupportedExtensions = new ArrayList<>();
        addAllSftpExtensions(sftpServerSupportedExtensions);
        // endregion

        // region general SFTP settings
        respectSftpAttributesFlags = true;
        // endregion

    }

    public static void addAllSftpExtensions(List<SftpAbstractExtension<?>> extensions) {
        extensions.add(new SftpExtensionCheckFile());
        extensions.add(new SftpExtensionCopyData());
        extensions.add(new SftpExtensionCopyFile());
        extensions.add(new SftpExtensionExpandPath());
        extensions.add(new SftpExtensionFileStatVfs());
        extensions.add(new SftpExtensionFileSync());
        extensions.add(new SftpExtensionGetTempFolder());
        extensions.add(new SftpExtensionHardlink());
        extensions.add(new SftpExtensionHomeDirectory());
        extensions.add(new SftpExtensionLimits());
        extensions.add(new SftpExtensionLinkSetStat());
        extensions.add(new SftpExtensionMakeTempFolder());
        extensions.add(new SftpExtensionPosixRename());
        extensions.add(new SftpExtensionSpaceAvailable());
        extensions.add(new SftpExtensionStatVfs());
        extensions.add(new SftpExtensionUsersGroupsById());
        extensions.add(new SftpExtensionVendorId());
        extensions.add(new SftpExtensionTextSeek());
        extensions.add(new SftpExtensionNewline());
    }

    // endregion

    // region copy constructor

    public Config(Config other) {
        super();
        defaultClientConnection =
                other.defaultClientConnection != null
                        ? other.defaultClientConnection.createCopy()
                        : null;
        defaultServerConnection =
                other.defaultServerConnection != null
                        ? other.defaultServerConnection.createCopy()
                        : null;
        defaultRunningMode = other.defaultRunningMode;
        clientVersion = other.clientVersion;
        clientComment = other.clientComment;
        clientEndOfMessageSequence = other.clientEndOfMessageSequence;
        serverVersion = other.serverVersion;
        serverComment = other.serverComment;
        serverEndOfMessageSequence = other.serverEndOfMessageSequence;
        clientCookie = other.clientCookie != null ? other.clientCookie.clone() : null;
        serverCookie = other.serverCookie != null ? other.serverCookie.clone() : null;
        clientSupportedKeyExchangeAlgorithms =
                other.clientSupportedKeyExchangeAlgorithms != null
                        ? new ArrayList<>(other.clientSupportedKeyExchangeAlgorithms)
                        : null;
        serverSupportedKeyExchangeAlgorithms =
                other.serverSupportedKeyExchangeAlgorithms != null
                        ? new ArrayList<>(other.serverSupportedKeyExchangeAlgorithms)
                        : null;
        clientSupportedHostKeyAlgorithms =
                other.clientSupportedHostKeyAlgorithms != null
                        ? new ArrayList<>(other.clientSupportedHostKeyAlgorithms)
                        : null;
        serverSupportedHostKeyAlgorithms =
                other.serverSupportedHostKeyAlgorithms != null
                        ? new ArrayList<>(other.serverSupportedHostKeyAlgorithms)
                        : null;
        clientSupportedEncryptionAlgorithmsClientToServer =
                other.clientSupportedEncryptionAlgorithmsClientToServer != null
                        ? new ArrayList<>(other.clientSupportedEncryptionAlgorithmsClientToServer)
                        : null;
        clientSupportedEncryptionAlgorithmsServerToClient =
                other.clientSupportedEncryptionAlgorithmsServerToClient != null
                        ? new ArrayList<>(other.clientSupportedEncryptionAlgorithmsServerToClient)
                        : null;
        serverSupportedEncryptionAlgorithmsServerToClient =
                other.serverSupportedEncryptionAlgorithmsServerToClient != null
                        ? new ArrayList<>(other.serverSupportedEncryptionAlgorithmsServerToClient)
                        : null;
        serverSupportedEncryptionAlgorithmsClientToServer =
                other.serverSupportedEncryptionAlgorithmsClientToServer != null
                        ? new ArrayList<>(other.serverSupportedEncryptionAlgorithmsClientToServer)
                        : null;
        clientSupportedMacAlgorithmsClientToServer =
                other.clientSupportedMacAlgorithmsClientToServer != null
                        ? new ArrayList<>(other.clientSupportedMacAlgorithmsClientToServer)
                        : null;
        clientSupportedMacAlgorithmsServerToClient =
                other.clientSupportedMacAlgorithmsServerToClient != null
                        ? new ArrayList<>(other.clientSupportedMacAlgorithmsServerToClient)
                        : null;
        serverSupportedMacAlgorithmsServerToClient =
                other.serverSupportedMacAlgorithmsServerToClient != null
                        ? new ArrayList<>(other.serverSupportedMacAlgorithmsServerToClient)
                        : null;
        serverSupportedMacAlgorithmsClientToServer =
                other.serverSupportedMacAlgorithmsClientToServer != null
                        ? new ArrayList<>(other.serverSupportedMacAlgorithmsClientToServer)
                        : null;
        clientSupportedCompressionMethodsClientToServer =
                other.clientSupportedCompressionMethodsClientToServer != null
                        ? new ArrayList<>(other.clientSupportedCompressionMethodsClientToServer)
                        : null;
        clientSupportedCompressionMethodsServerToClient =
                other.clientSupportedCompressionMethodsServerToClient != null
                        ? new ArrayList<>(other.clientSupportedCompressionMethodsServerToClient)
                        : null;
        serverSupportedCompressionMethodsServerToClient =
                other.serverSupportedCompressionMethodsServerToClient != null
                        ? new ArrayList<>(other.serverSupportedCompressionMethodsServerToClient)
                        : null;
        serverSupportedCompressionMethodsClientToServer =
                other.serverSupportedCompressionMethodsClientToServer != null
                        ? new ArrayList<>(other.serverSupportedCompressionMethodsClientToServer)
                        : null;
        clientSupportedLanguagesClientToServer =
                other.clientSupportedLanguagesClientToServer != null
                        ? new ArrayList<>(other.clientSupportedLanguagesClientToServer)
                        : null;
        clientSupportedLanguagesServerToClient =
                other.clientSupportedLanguagesServerToClient != null
                        ? new ArrayList<>(other.clientSupportedLanguagesServerToClient)
                        : null;
        serverSupportedLanguagesServerToClient =
                other.serverSupportedLanguagesServerToClient != null
                        ? new ArrayList<>(other.serverSupportedLanguagesServerToClient)
                        : null;
        serverSupportedLanguagesClientToServer =
                other.serverSupportedLanguagesClientToServer != null
                        ? new ArrayList<>(other.serverSupportedLanguagesClientToServer)
                        : null;
        clientFirstKeyExchangePacketFollows = other.clientFirstKeyExchangePacketFollows;
        serverFirstKeyExchangePacketFollows = other.serverFirstKeyExchangePacketFollows;
        clientReserved = other.clientReserved;
        serverReserved = other.serverReserved;
        dhGexMinimalGroupSize = other.dhGexMinimalGroupSize;
        dhGexPreferredGroupSize = other.dhGexPreferredGroupSize;
        dhGexMaximalGroupSize = other.dhGexMaximalGroupSize;
        defaultDhKeyExchangeAlgorithm = other.defaultDhKeyExchangeAlgorithm;
        defaultEcdhKeyExchangeAlgorithm = other.defaultEcdhKeyExchangeAlgorithm;
        defaultRsaKeyExchangeAlgorithm = other.defaultRsaKeyExchangeAlgorithm;
        defaultHybridKeyExchangeAlgorithm = other.defaultHybridKeyExchangeAlgorithm;
        enableEncryptionOnNewKeysMessage = other.enableEncryptionOnNewKeysMessage;
        forcePacketCipherChange = other.forcePacketCipherChange;
        enforceSettings = other.enforceSettings;
        if (other.hostKeys != null) {
            hostKeys = new ArrayList<>(other.hostKeys.size());
            for (SshPublicKey<?, ?> item : other.hostKeys) {
                hostKeys.add(item != null ? item.createCopy() : null);
            }
        }
        fallbackRsaTransientPublicKey =
                other.fallbackRsaTransientPublicKey != null
                        ? other.fallbackRsaTransientPublicKey.createCopy()
                        : null;
        if (other.clientSupportedExtensions != null) {
            clientSupportedExtensions = new ArrayList<>(other.clientSupportedExtensions.size());
            for (AbstractExtension<?> item : other.clientSupportedExtensions) {
                clientSupportedExtensions.add(item != null ? item.createCopy() : null);
            }
        }
        if (other.serverSupportedExtensions != null) {
            serverSupportedExtensions = new ArrayList<>(other.serverSupportedExtensions.size());
            for (AbstractExtension<?> item : other.serverSupportedExtensions) {
                serverSupportedExtensions.add(item != null ? item.createCopy() : null);
            }
        }
        respectServerSigAlgsExtension = other.respectServerSigAlgsExtension;
        serverSupportedPublicKeyAlgorithmsForAuthentication =
                other.serverSupportedPublicKeyAlgorithmsForAuthentication != null
                        ? new ArrayList<>(other.serverSupportedPublicKeyAlgorithmsForAuthentication)
                        : null;
        clientSupportedDelayCompressionMethods =
                other.clientSupportedDelayCompressionMethods != null
                        ? new ArrayList<>(other.clientSupportedDelayCompressionMethods)
                        : null;
        serverSupportedDelayCompressionMethods =
                other.serverSupportedDelayCompressionMethods != null
                        ? new ArrayList<>(other.serverSupportedDelayCompressionMethods)
                        : null;
        respectDelayCompressionExtension = other.respectDelayCompressionExtension;
        authenticationMethod = other.authenticationMethod;
        serviceName = other.serviceName;
        username = other.username;
        password = other.password;
        if (other.preConfiguredAuthResponses != null) {
            preConfiguredAuthResponses = new ArrayList<>(other.preConfiguredAuthResponses.size());
            for (AuthenticationResponseEntries item : other.preConfiguredAuthResponses) {
                preConfiguredAuthResponses.add(item != null ? item.createCopy() : null);
            }
        }
        if (other.preConfiguredAuthPrompts != null) {
            preConfiguredAuthPrompts = new ArrayList<>(other.preConfiguredAuthPrompts.size());
            for (AuthenticationPromptEntries item : other.preConfiguredAuthPrompts) {
                preConfiguredAuthPrompts.add(item != null ? item.createCopy() : null);
            }
        }
        if (other.userKeys != null) {
            userKeys = new ArrayList<>(other.userKeys.size());
            for (SshPublicKey<?, ?> item : other.userKeys) {
                userKeys.add(item != null ? item.createCopy() : null);
            }
        }
        channelCommand = other.channelCommand;
        channelDefaults = other.channelDefaults != null ? other.channelDefaults.createCopy() : null;
        reopenChannelOnClose = other.reopenChannelOnClose;
        replyWanted = other.replyWanted;
        defaultVariableName = other.defaultVariableName;
        defaultVariableValue = other.defaultVariableValue;
        clientFlowControl = other.clientFlowControl;
        defaultTerminalWidthPixels = other.defaultTerminalWidthPixels;
        defaultTerminalWidthColumns = other.defaultTerminalWidthColumns;
        defaultTerminalHeightRows = other.defaultTerminalHeightRows;
        defaultTerminalHeightPixels = other.defaultTerminalHeightPixels;
        defaultTermEnvVariable = other.defaultTermEnvVariable;
        defaultSubsystemName = other.defaultSubsystemName;
        defaultBreakLength = other.defaultBreakLength;
        fallbackToNoDecryptionOnError = other.fallbackToNoDecryptionOnError;
        fallbackToNoDecompressionOnError = other.fallbackToNoDecompressionOnError;
        sftpClientVersion = other.sftpClientVersion;
        sftpServerVersion = other.sftpServerVersion;
        sftpNegotiatedVersion = other.sftpNegotiatedVersion;
        if (other.sftpClientSupportedExtensions != null) {
            sftpClientSupportedExtensions =
                    new ArrayList<>(other.sftpClientSupportedExtensions.size());
            for (SftpAbstractExtension<?> item : other.sftpClientSupportedExtensions) {
                sftpClientSupportedExtensions.add(item != null ? item.createCopy() : null);
            }
        }
        if (other.sftpServerSupportedExtensions != null) {
            sftpServerSupportedExtensions =
                    new ArrayList<>(other.sftpServerSupportedExtensions.size());
            for (SftpAbstractExtension<?> item : other.sftpServerSupportedExtensions) {
                sftpServerSupportedExtensions.add(item != null ? item.createCopy() : null);
            }
        }
        respectSftpAttributesFlags = other.respectSftpAttributesFlags;
        workflowInput = other.workflowInput;
        workflowTraceType = other.workflowTraceType;
        outputFilters = other.outputFilters != null ? new ArrayList<>(other.outputFilters) : null;
        workflowOutput = other.workflowOutput;
        workflowExecutorType = other.workflowExecutorType;
        applyFiltersInPlace = other.applyFiltersInPlace;
        filtersKeepUserSettings = other.filtersKeepUserSettings;
        workflowExecutorShouldOpen = other.workflowExecutorShouldOpen;
        stopActionsAfterDisconnect = other.stopActionsAfterDisconnect;
        handleTimeoutOnReceiveAsIOException = other.handleTimeoutOnReceiveAsIOException;
        stopActionsAfterIOException = other.stopActionsAfterIOException;
        workflowExecutorShouldClose = other.workflowExecutorShouldClose;
        resetWorkflowTraceBeforeExecution = other.resetWorkflowTraceBeforeExecution;
        resetWorkflowTraceBeforeSaving = other.resetWorkflowTraceBeforeSaving;
        resetModifiableVariables = other.resetModifiableVariables;
        resetClientSourcePort = other.resetClientSourcePort;
        retryFailedClientTcpSocketInitialization = other.retryFailedClientTcpSocketInitialization;
        stopTraceAfterUnexpected = other.stopTraceAfterUnexpected;
        allowDynamicGenerationOfActions = other.allowDynamicGenerationOfActions;
        addDynamicallyGeneratedActionsToWorkflowTrace =
                other.addDynamicallyGeneratedActionsToWorkflowTrace;
        quickReceive = other.quickReceive;
        endReceivingEarly = other.endReceivingEarly;
        receiveMaximumBytes = other.receiveMaximumBytes;
        stopReceivingAfterDisconnect = other.stopReceivingAfterDisconnect;
        configOutput = other.configOutput;
        chooserType = other.chooserType;
    }

    public Config createCopy() {
        return new Config(this);
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
        ConfigCache cachedConfig = PATH_CONFIG_CACHE.get(file);
        if (cachedConfig != null) {
            return cachedConfig.getCachedCopy();
        }
        Config resultConfig = ConfigIO.read(file);
        PATH_CONFIG_CACHE.put(file, new ConfigCache(resultConfig.createCopy()));
        return resultConfig;
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

    // region storeConfig
    /** Serialize and write config to file. */
    public void storeConfig() {
        Random random = new Random();
        String configOutputName = configOutput;
        if (configOutputName != null && !configOutputName.isEmpty()) {
            try {

                File file = new File(configOutputName);
                if (file.isDirectory()) {
                    configOutputName = "config-" + random.nextInt() + ".xml";
                    file = new File(file, configOutputName);
                }
                ConfigIO.write(this, file);
            } catch (RuntimeException ex) {
                LOGGER.info("Could not serialize Config.");
                LOGGER.debug(ex);
            }
        }
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
            ArrayList<KeyExchangeAlgorithm> clientSupportedKeyExchangeAlgorithms) {
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

    public List<LanguageTag> getClientSupportedLanguagesClientToServer() {
        return clientSupportedLanguagesClientToServer;
    }

    public List<LanguageTag> getClientSupportedLanguagesServerToClient() {
        return clientSupportedLanguagesServerToClient;
    }

    public List<LanguageTag> getServerSupportedLanguagesServerToClient() {
        return serverSupportedLanguagesServerToClient;
    }

    public List<LanguageTag> getServerSupportedLanguagesClientToServer() {
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
            ArrayList<KeyExchangeAlgorithm> serverSupportedKeyExchangeAlgorithms) {
        this.serverSupportedKeyExchangeAlgorithms = serverSupportedKeyExchangeAlgorithms;
    }

    public void setClientSupportedHostKeyAlgorithms(
            ArrayList<PublicKeyAlgorithm> clientSupportedHostKeyAlgorithms) {
        this.clientSupportedHostKeyAlgorithms = clientSupportedHostKeyAlgorithms;
    }

    public void setServerSupportedHostKeyAlgorithms(
            ArrayList<PublicKeyAlgorithm> serverSupportedHostKeyAlgorithms) {
        this.serverSupportedHostKeyAlgorithms = serverSupportedHostKeyAlgorithms;
    }

    public void setClientSupportedEncryptionAlgorithmsClientToServer(
            ArrayList<EncryptionAlgorithm> clientSupportedEncryptionAlgorithmsClientToServer) {
        this.clientSupportedEncryptionAlgorithmsClientToServer =
                clientSupportedEncryptionAlgorithmsClientToServer;
    }

    public void setClientSupportedEncryptionAlgorithmsServerToClient(
            ArrayList<EncryptionAlgorithm> clientSupportedEncryptionAlgorithmsServerToClient) {
        this.clientSupportedEncryptionAlgorithmsServerToClient =
                clientSupportedEncryptionAlgorithmsServerToClient;
    }

    public void setServerSupportedEncryptionAlgorithmsServerToClient(
            ArrayList<EncryptionAlgorithm> serverSupportedEncryptionAlgorithmsServerToClient) {
        this.serverSupportedEncryptionAlgorithmsServerToClient =
                serverSupportedEncryptionAlgorithmsServerToClient;
    }

    public void setServerSupportedEncryptionAlgorithmsClientToServer(
            ArrayList<EncryptionAlgorithm> serverSupportedEncryptionAlgorithmsClientToServer) {
        this.serverSupportedEncryptionAlgorithmsClientToServer =
                serverSupportedEncryptionAlgorithmsClientToServer;
    }

    public void setClientSupportedMacAlgorithmsClientToServer(
            ArrayList<MacAlgorithm> clientSupportedMacAlgorithmsClientToServer) {
        this.clientSupportedMacAlgorithmsClientToServer =
                clientSupportedMacAlgorithmsClientToServer;
    }

    public void setClientSupportedMacAlgorithmsServerToClient(
            ArrayList<MacAlgorithm> clientSupportedMacAlgorithmsServerToClient) {
        this.clientSupportedMacAlgorithmsServerToClient =
                clientSupportedMacAlgorithmsServerToClient;
    }

    public void setServerSupportedMacAlgorithmsServerToClient(
            ArrayList<MacAlgorithm> serverSupportedMacAlgorithmsServerToClient) {
        this.serverSupportedMacAlgorithmsServerToClient =
                serverSupportedMacAlgorithmsServerToClient;
    }

    public void setServerSupportedMacAlgorithmsClientToServer(
            ArrayList<MacAlgorithm> serverSupportedMacAlgorithmsClientToServer) {
        this.serverSupportedMacAlgorithmsClientToServer =
                serverSupportedMacAlgorithmsClientToServer;
    }

    public void setClientSupportedCompressionMethodsClientToServer(
            ArrayList<CompressionMethod> clientSupportedCompressionMethodsClientToServer) {
        this.clientSupportedCompressionMethodsClientToServer =
                clientSupportedCompressionMethodsClientToServer;
    }

    public void setClientSupportedCompressionMethodsServerToClient(
            ArrayList<CompressionMethod> clientSupportedCompressionMethodsServerToClient) {
        this.clientSupportedCompressionMethodsServerToClient =
                clientSupportedCompressionMethodsServerToClient;
    }

    public void setServerSupportedCompressionMethodsServerToClient(
            ArrayList<CompressionMethod> serverSupportedCompressionMethodsServerToClient) {
        this.serverSupportedCompressionMethodsServerToClient =
                serverSupportedCompressionMethodsServerToClient;
    }

    public void setServerSupportedCompressionMethodsClientToServer(
            ArrayList<CompressionMethod> serverSupportedCompressionMethodsClientToServer) {
        this.serverSupportedCompressionMethodsClientToServer =
                serverSupportedCompressionMethodsClientToServer;
    }

    public void setClientSupportedLanguagesClientToServer(
            ArrayList<LanguageTag> clientSupportedLanguagesClientToServer) {
        this.clientSupportedLanguagesClientToServer = clientSupportedLanguagesClientToServer;
    }

    public void setClientSupportedLanguagesServerToClient(
            ArrayList<LanguageTag> clientSupportedLanguagesServerToClient) {
        this.clientSupportedLanguagesServerToClient = clientSupportedLanguagesServerToClient;
    }

    public void setServerSupportedLanguagesServerToClient(
            ArrayList<LanguageTag> serverSupportedLanguagesServerToClient) {
        this.serverSupportedLanguagesServerToClient = serverSupportedLanguagesServerToClient;
    }

    public void setServerSupportedLanguagesClientToServer(
            ArrayList<LanguageTag> serverSupportedLanguagesClientToServer) {
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
    public ArrayList<AbstractExtension<?>> getClientSupportedExtensions() {
        return clientSupportedExtensions;
    }

    public ArrayList<AbstractExtension<?>> getServerSupportedExtensions() {
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
    public void setClientSupportedExtensions(
            ArrayList<AbstractExtension<?>> clientSupportedExtensions) {
        this.clientSupportedExtensions = clientSupportedExtensions;
    }

    public void setServerSupportedExtensions(
            ArrayList<AbstractExtension<?>> serverSupportedExtensions) {
        this.serverSupportedExtensions = serverSupportedExtensions;
    }

    // section server-sig-algs extension
    public void setServerSupportedPublicKeyAlgorithmsForAuthentication(
            ArrayList<PublicKeyAlgorithm> serverSupportedPublicKeyAlgorithmsForAuthentication) {
        this.serverSupportedPublicKeyAlgorithmsForAuthentication =
                serverSupportedPublicKeyAlgorithmsForAuthentication;
    }

    public void setRespectServerSigAlgsExtension(boolean respectServerSigAlgsExtension) {
        this.respectServerSigAlgsExtension = respectServerSigAlgsExtension;
    }

    // section delay-compression extension
    public void setClientSupportedDelayCompressionMethods(
            ArrayList<CompressionMethod> clientSupportedDelayCompressionMethods) {
        this.clientSupportedDelayCompressionMethods = clientSupportedDelayCompressionMethods;
    }

    public void setServerSupportedDelayCompressionMethods(
            ArrayList<CompressionMethod> serverSupportedDelayCompressionMethods) {
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

    public ConnectionDirection getEnableEncryptionOnNewKeysMessage() {
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

    public void setEnableEncryptionOnNewKeysMessage(
            ConnectionDirection enableEncryptionOnNewKeysMessage) {
        this.enableEncryptionOnNewKeysMessage = enableEncryptionOnNewKeysMessage;
    }

    public void setForcePacketCipherChange(Boolean forcePacketCipherChange) {
        this.forcePacketCipherChange = forcePacketCipherChange;
    }

    public void setEnforceSettings(Boolean enforceSettings) {
        this.enforceSettings = enforceSettings;
    }

    public void setHostKeys(List<SshPublicKey<?, ?>> hostKeys) {
        this.hostKeys = new ArrayList<>(Objects.requireNonNull(hostKeys));
    }

    public void setHostKeys(ArrayList<SshPublicKey<?, ?>> hostKeys) {
        this.hostKeys = Objects.requireNonNull(hostKeys);
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

    public ArrayList<AuthenticationResponseEntries> getPreConfiguredAuthResponses() {
        return preConfiguredAuthResponses;
    }

    public ArrayList<AuthenticationPromptEntries> getPreConfiguredAuthPrompts() {
        return preConfiguredAuthPrompts;
    }

    public List<SshPublicKey<?, ?>> getUserKeys() {
        return userKeys;
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
            ArrayList<AuthenticationResponseEntries> preConfiguredAuthResponses) {
        this.preConfiguredAuthResponses = preConfiguredAuthResponses;
    }

    public void setPreConfiguredAuthPrompts(
            ArrayList<AuthenticationPromptEntries> preConfiguredAuthPrompts) {
        this.preConfiguredAuthPrompts = preConfiguredAuthPrompts;
    }

    public void setUserKeys(List<SshPublicKey<?, ?>> userKeys) {
        this.userKeys = new ArrayList<>(Objects.requireNonNull(userKeys));
    }

    public void setUserKeys(ArrayList<SshPublicKey<?, ?>> userKeys) {
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

    public Boolean getReopenChannelOnClose() {
        return reopenChannelOnClose;
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

    public void setReopenChannelOnClose(Boolean reopenChannelOnClose) {
        this.reopenChannelOnClose = reopenChannelOnClose;
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

    // region general SSH settings
    public Boolean getFallbackToNoDecryptionOnError() {
        return fallbackToNoDecryptionOnError;
    }

    public void setFallbackToNoDecryptionOnError(Boolean fallbackToNoDecryptionOnError) {
        this.fallbackToNoDecryptionOnError = fallbackToNoDecryptionOnError;
    }

    public Boolean getFallbackToNoDecompressionOnError() {
        return fallbackToNoDecompressionOnError;
    }

    public void setFallbackToNoDecompressionOnError(Boolean fallbackToNoDecompressionOnError) {
        this.fallbackToNoDecompressionOnError = fallbackToNoDecompressionOnError;
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

    public Boolean isStopActionsAfterDisconnect() {
        return stopActionsAfterDisconnect;
    }

    public Boolean getHandleTimeoutOnReceiveAsIOException() {
        return handleTimeoutOnReceiveAsIOException;
    }

    public Boolean getStopActionsAfterIOException() {
        return stopActionsAfterIOException;
    }

    public Boolean getWorkflowExecutorShouldClose() {
        return workflowExecutorShouldClose;
    }

    public Boolean getResetWorkflowTraceBeforeExecution() {
        return resetWorkflowTraceBeforeExecution;
    }

    public Boolean getResetWorkflowTraceBeforeSaving() {
        return resetWorkflowTraceBeforeSaving;
    }

    public Boolean getResetModifiableVariables() {
        return resetModifiableVariables;
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

    public Boolean getAllowDynamicGenerationOfActions() {
        return allowDynamicGenerationOfActions;
    }

    public Boolean getAddDynamicallyGeneratedActionsToWorkflowTrace() {
        return addDynamicallyGeneratedActionsToWorkflowTrace;
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

    public void setOutputFilters(ArrayList<FilterType> outputFilters) {
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

    public void setHandleTimeoutOnReceiveAsIOException(
            Boolean handleTimeoutOnReceiveAsIOException) {
        this.handleTimeoutOnReceiveAsIOException = handleTimeoutOnReceiveAsIOException;
    }

    public void setStopActionsAfterIOException(Boolean stopActionsAfterIOException) {
        this.stopActionsAfterIOException = stopActionsAfterIOException;
    }

    public void setWorkflowExecutorShouldClose(Boolean workflowExecutorShouldClose) {
        this.workflowExecutorShouldClose = workflowExecutorShouldClose;
    }

    public void setResetWorkflowTraceBeforeExecution(Boolean resetWorkflowTraceBeforeExecution) {
        this.resetWorkflowTraceBeforeExecution = resetWorkflowTraceBeforeExecution;
    }

    public void setResetWorkflowTraceBeforeSaving(Boolean resetWorkflowTraceBeforeSaving) {
        this.resetWorkflowTraceBeforeSaving = resetWorkflowTraceBeforeSaving;
    }

    public void setResetModifiableVariables(Boolean resetModifiableVariables) {
        this.resetModifiableVariables = resetModifiableVariables;
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

    public void setAllowDynamicGenerationOfActions(Boolean allowDynamicGenerationOfActions) {
        this.allowDynamicGenerationOfActions = allowDynamicGenerationOfActions;
    }

    public void setAddDynamicallyGeneratedActionsToWorkflowTrace(
            Boolean addDynamicallyGeneratedActionsToWorkflowTrace) {
        this.addDynamicallyGeneratedActionsToWorkflowTrace =
                addDynamicallyGeneratedActionsToWorkflowTrace;
    }

    // endregion

    // region Getters for ReceiveAction
    public Boolean isQuickReceive() {
        return quickReceive;
    }

    public Integer getReceiveMaximumBytes() {
        return receiveMaximumBytes;
    }

    public Boolean isEndReceivingEarly() {
        return endReceivingEarly;
    }

    public void setEndReceivingEarly(Boolean endReceivingEarly) {
        this.endReceivingEarly = endReceivingEarly;
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

    // region Getters for SFTP Version Exchange
    public Integer getSftpClientVersion() {
        return sftpClientVersion;
    }

    public Integer getSftpServerVersion() {
        return sftpServerVersion;
    }

    public Integer getSftpNegotiatedVersion() {
        return sftpNegotiatedVersion;
    }

    // endregion
    // region Setters for SFTP Version Exchange
    public void setSftpClientVersion(Integer sftpClientVersion) {
        this.sftpClientVersion = sftpClientVersion;
    }

    public void setSftpServerVersion(Integer sftpServerVersion) {
        this.sftpServerVersion = sftpServerVersion;
    }

    public void setSftpNegotiatedVersion(Integer sftpNegotiatedVersion) {
        this.sftpNegotiatedVersion = sftpNegotiatedVersion;
    }

    // endregion

    // region Getters SFTP Extensions

    // section general extensions
    public ArrayList<SftpAbstractExtension<?>> getSftpClientSupportedExtensions() {
        return sftpClientSupportedExtensions;
    }

    public ArrayList<SftpAbstractExtension<?>> getSftpServerSupportedExtensions() {
        return sftpServerSupportedExtensions;
    }

    // endregion

    // region Setters SFTP Extensions

    // section general extensions
    public void setSftpClientSupportedExtensions(
            ArrayList<SftpAbstractExtension<?>> sftpClientSupportedExtensions) {
        this.sftpClientSupportedExtensions = sftpClientSupportedExtensions;
    }

    public void setSftpServerSupportedExtensions(
            ArrayList<SftpAbstractExtension<?>> sftpServerSupportedExtensions) {
        this.sftpServerSupportedExtensions = sftpServerSupportedExtensions;
    }

    // endregion

    // region general SFTP settings
    public void setRespectSftpAttributesFlags(Boolean respectSftpAttributesFlags) {
        this.respectSftpAttributesFlags = respectSftpAttributesFlags;
    }

    public Boolean getRespectSftpAttributesFlags() {
        return respectSftpAttributesFlags;
    }
    // endregion
}
