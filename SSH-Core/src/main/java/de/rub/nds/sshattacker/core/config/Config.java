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
import de.rub.nds.sshattacker.core.crypto.keys.RsaPublicKey;
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

    private final String serverVersion;

    private final String serverComment;

    @XmlJavaTypeAdapter(UnformattedByteArrayAdapter.class)
    private final byte[] clientCookie;

    @XmlJavaTypeAdapter(UnformattedByteArrayAdapter.class)
    private final byte[] serverCookie;

    private String endOfMessageSequence;

    @XmlElement(name = "clientSupportedKeyExchangeAlgorithm")
    @XmlElementWrapper
    private List<KeyExchangeAlgorithm> clientSupportedKeyExchangeAlgorithms;

    @XmlElement(name = "serverSupportedKeyExchangeAlgorithm")
    @XmlElementWrapper
    private final List<KeyExchangeAlgorithm> serverSupportedKeyExchangeAlgorithms;

    @XmlElement(name = "clientSupportedHostKeyAlgorithm")
    @XmlElementWrapper
    private final List<PublicKeyAuthenticationAlgorithm> clientSupportedHostKeyAlgorithms;

    @XmlElement(name = "serverSupportedHostKeyAlgorithm")
    @XmlElementWrapper
    private final List<PublicKeyAuthenticationAlgorithm> serverSupportedHostKeyAlgorithms;

    @XmlElement(name = "clientSupportedCipherAlgorithmClientToServer")
    @XmlElementWrapper
    private final List<EncryptionAlgorithm> clientSupportedCipherAlgorithmsClientToServer;

    @XmlElement(name = "clientSupportedCipherAlgorithmServerToClient")
    @XmlElementWrapper
    private final List<EncryptionAlgorithm> clientSupportedCipherAlgorithmsServerToClient;

    @XmlElement(name = "serverSupportedCipherAlgorithmServerToClient")
    @XmlElementWrapper
    private final List<EncryptionAlgorithm> serverSupportedCipherAlgorithmsServerToClient;

    @XmlElement(name = "serverSupportedCipherAlgorithmClientToServer")
    @XmlElementWrapper
    private final List<EncryptionAlgorithm> serverSupportedCipherAlgorithmsClientToServer;

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

    @XmlJavaTypeAdapter(UnformattedByteArrayAdapter.class)
    private byte[] clientEcdhPublicKey;

    @XmlJavaTypeAdapter(UnformattedByteArrayAdapter.class)
    private byte[] serverEcdhPublicKey;

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
     * If set to true, preparation exceptions will not be thrown during message preparation.
     * Instead, fields will be filled with dummy data to allow for out of order testing.
     */
    private Boolean avoidPreparationExceptions = false;

    /**
     * If set to true, adjustment exceptions will not be thrown during message handling. Instead,
     * message related adjustments may be skipped depending on the current state.
     */
    private Boolean avoidAdjustmentExceptions = false;

    /**
     * If set to true, sending or receiving a NewKeysMessage automatically enables the encryption
     * for the corresponding transport direction. If set to false, encryption must be enabled
     * manually by calling the corresponding methods on the state.
     */
    private Boolean enableEncryptionOnNewKeysMessage = false;

    private ChooserType chooserType = ChooserType.DEFAULT;

    private NamedDHGroup defaultDHGexKeyExchangeGroup;

    private KeyExchangeAlgorithm defaultEcdhKeyExchangeAlgortihm;

    private KeyExchangeAlgorithm defaultRsaKeyExchangeAlgorithm;

    private RsaPublicKey defaultRsaPublicKey;

    public Config() {

        defaultClientConnection = new OutboundConnection("client", 65222, "localhost");
        defaultServerConnection = new InboundConnection("server", 65222, "localhost");
        clientVersion = "SSH-2.0-OpenSSH_7.8";
        clientComment = "";
        serverVersion = clientVersion;
        serverComment = clientComment;
        clientCookie = ArrayConverter.hexStringToByteArray("00000000000000000000000000000000");
        serverCookie = ArrayConverter.hexStringToByteArray("00000000000000000000000000000000");
        endOfMessageSequence = "\r\n";

        clientSupportedKeyExchangeAlgorithms = new LinkedList<>();
        clientSupportedKeyExchangeAlgorithms.add(
                KeyExchangeAlgorithm.DIFFIE_HELLMAN_GROUP14_SHA256);
        clientSupportedKeyExchangeAlgorithms.add(
                KeyExchangeAlgorithm.DIFFIE_HELLMAN_GROUP_EXCHANGE_SHA256);
        clientSupportedKeyExchangeAlgorithms.add(KeyExchangeAlgorithm.ECDH_SHA2_NISTP256);

        serverSupportedKeyExchangeAlgorithms =
                new LinkedList<>(clientSupportedKeyExchangeAlgorithms);

        clientSupportedHostKeyAlgorithms = new LinkedList<>();
        clientSupportedHostKeyAlgorithms.add(PublicKeyAuthenticationAlgorithm.SSH_RSA);
        serverSupportedHostKeyAlgorithms = new LinkedList<>(clientSupportedHostKeyAlgorithms);

        clientSupportedCipherAlgorithmsClientToServer = new LinkedList<>();
        clientSupportedCipherAlgorithmsClientToServer.add(
                EncryptionAlgorithm.AES256_GCM_OPENSSH_COM);
        clientSupportedCipherAlgorithmsServerToClient =
                new LinkedList<>(clientSupportedCipherAlgorithmsClientToServer);
        serverSupportedCipherAlgorithmsClientToServer =
                new LinkedList<>(clientSupportedCipherAlgorithmsClientToServer);
        serverSupportedCipherAlgorithmsServerToClient =
                new LinkedList<>(clientSupportedCipherAlgorithmsClientToServer);

        clientSupportedMacAlgorithmsClientToServer = new LinkedList<>();
        clientSupportedMacAlgorithmsClientToServer.add(MacAlgorithm.HMAC_SHA2_256_ETM_OPENSSH_COM);
        clientSupportedMacAlgorithmsServerToClient =
                new LinkedList<>(clientSupportedMacAlgorithmsClientToServer);
        serverSupportedMacAlgorithmsServerToClient =
                new LinkedList<>(clientSupportedMacAlgorithmsClientToServer);
        serverSupportedMacAlgorithmsClientToServer =
                new LinkedList<>(clientSupportedMacAlgorithmsClientToServer);

        clientSupportedCompressionMethodsClientToServer = new LinkedList<>();
        clientSupportedCompressionMethodsClientToServer.add(CompressionMethod.NONE);
        clientSupportedCompressionMethodsClientToServer.add(CompressionMethod.ZLIB_OPENSSH_COM);
        clientSupportedCompressionMethodsClientToServer.add(CompressionMethod.ZLIB);
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

        defaultDHGexKeyExchangeGroup = NamedDHGroup.GROUP14;
        defaultEcdhKeyExchangeAlgortihm = KeyExchangeAlgorithm.ECDH_SHA2_NISTP256;

        defaultRsaKeyExchangeAlgorithm = KeyExchangeAlgorithm.RSA2048_SHA256;
        defaultRsaPublicKey =
                new RsaPublicKey(
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

    public String getEndOfMessageSequence() {
        return endOfMessageSequence;
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

    public Boolean getAvoidAdjustmentExceptions() {
        return avoidAdjustmentExceptions;
    }

    public void setAvoidAdjustmentExceptions(Boolean avoidAdjustmentExceptions) {
        this.avoidAdjustmentExceptions = avoidAdjustmentExceptions;
    }

    public Boolean getAvoidPreparationExceptions() {
        return avoidPreparationExceptions;
    }

    public void setAvoidPreparationExceptions(Boolean avoidPreparationExceptions) {
        this.avoidPreparationExceptions = avoidPreparationExceptions;
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

    public NamedDHGroup getDefaultDHGexKeyExchangeGroup() {
        return defaultDHGexKeyExchangeGroup;
    }

    public KeyExchangeAlgorithm getDefaultEcdhKeyExchangeAlgortihm() {
        return defaultEcdhKeyExchangeAlgortihm;
    }

    public Channel getDefaultChannel() {
        return defaultChannel;
    }

    public void setDefaultChannel(Channel defaultChannel) {
        this.defaultChannel = defaultChannel;
    }

    public KeyExchangeAlgorithm getDefaultRsaKeyExchangeAlgorithm() {
        return defaultRsaKeyExchangeAlgorithm;
    }

    public RsaPublicKey getDefaultRsaPublicKey() {
        return defaultRsaPublicKey;
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
