/**
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2021 Ruhr University Bochum, Paderborn University,
 * and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.config;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.sshattacker.core.connection.InboundConnection;
import de.rub.nds.sshattacker.core.connection.OutboundConnection;
import de.rub.nds.sshattacker.core.constants.*;
import de.rub.nds.sshattacker.core.workflow.factory.WorkflowTraceType;
import de.rub.nds.sshattacker.core.workflow.filter.FilterType;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.Serializable;
import java.lang.reflect.Field;
import java.util.ArrayList;
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
    private final String clientVersion;
    private final String clientComment;
    private final String serverVersion;
    private final String serverComment;
    private final byte[] clientCookie;
    private final byte[] serverCookie;
    private final List<KeyExchangeAlgorithm> clientSupportedKeyExchangeAlgorithms;
    private final List<KeyExchangeAlgorithm> serverSupportedKeyExchangeAlgorithms;
    private final List<PublicKeyAuthenticationAlgorithm> clientSupportedHostKeyAlgorithms;
    private final List<PublicKeyAuthenticationAlgorithm> serverSupportedHostKeyAlgorithms;
    private final List<EncryptionAlgorithm> clientSupportedCipherAlgorithmsClientToServer;
    private final List<EncryptionAlgorithm> clientSupportedCipherAlgorithmsServerToClient;
    private final List<EncryptionAlgorithm> serverSupportedCipherAlgorithmsServerToClient;
    private final List<EncryptionAlgorithm> serverSupportedCipherAlgorithmsClientToServer;
    private final List<MacAlgorithm> clientSupportedMacAlgorithmsClientToServer;
    private final List<MacAlgorithm> clientSupportedMacAlgorithmsServerToClient;
    private final List<MacAlgorithm> serverSupportedMacAlgorithmsServerToClient;
    private final List<MacAlgorithm> serverSupportedMacAlgorithmsClientToServer;
    private final List<CompressionAlgorithm> clientSupportedCompressionAlgorithmsClientToServer;
    private final List<CompressionAlgorithm> clientSupportedCompressionAlgorithmsServerToClient;
    private final List<CompressionAlgorithm> serverSupportedCompressionAlgorithmsServerToClient;
    private final List<CompressionAlgorithm> serverSupportedCompressionAlgorithmsClientToServer;
    private final List<String> clientSupportedLanguagesClientToServer;
    private final List<String> clientSupportedLanguagesServerToClient;
    private final List<String> serverSupportedLanguagesServerToClient;
    private final List<String> serverSupportedLanguagesClientToServer;
    private final boolean clientFirstKeyExchangePacketFollows;
    private final boolean serverFirstKeyExchangePacketFollows;
    private final int clientReserved;
    private final int serverReserved;

    private byte[] clientEcdhPublicKey;
    private byte[] serverEcdhPublicKey;

    private AuthenticationMethod authenticationMethod;
    private String serviceName;
    private String username;
    private String password;
    private int localChannel;
    private int remoteChannel;
    private int windowSize;
    private int packetSize;
    private ChannelType channelType;
    private ChannelRequestType channelRequestType;
    private String channelCommand;
    private byte replyWanted;

    /**
     * Default Connection to use when running as Client
     */
    private OutboundConnection defaultClientConnection;

    /**
     * Default Connection to use when running as Server
     */
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

    private Boolean resetWorkflowtracesBeforeSaving = true;

    private String configOutput = null;

    private Boolean enforceSettings = false;

    public Config() {

        defaultClientConnection = new OutboundConnection(65222, "localhost");
        defaultServerConnection = new InboundConnection("server", 65222, "localhost");
        clientVersion = "SSH-2.0-OpenSSH_7.8";
        clientComment = "";
        serverVersion = clientVersion;
        serverComment = clientComment;
        clientCookie = ArrayConverter.hexStringToByteArray("00000000000000000000000000000000");
        serverCookie = ArrayConverter.hexStringToByteArray("00000000000000000000000000000000");

        clientSupportedKeyExchangeAlgorithms = new LinkedList<>();
        clientSupportedKeyExchangeAlgorithms.add(KeyExchangeAlgorithm.ECDH_SHA2_NISTP256);
        serverSupportedKeyExchangeAlgorithms = new LinkedList<>(clientSupportedKeyExchangeAlgorithms);

        clientSupportedHostKeyAlgorithms = new LinkedList<>();
        clientSupportedHostKeyAlgorithms.add(PublicKeyAuthenticationAlgorithm.SSH_RSA);
        serverSupportedHostKeyAlgorithms = new LinkedList<>(clientSupportedHostKeyAlgorithms);

        clientSupportedCipherAlgorithmsClientToServer = new LinkedList<>();
        clientSupportedCipherAlgorithmsClientToServer.add(EncryptionAlgorithm.AES128_CBC);
        clientSupportedCipherAlgorithmsServerToClient = new LinkedList<>(clientSupportedCipherAlgorithmsClientToServer);
        serverSupportedCipherAlgorithmsClientToServer = new LinkedList<>(clientSupportedCipherAlgorithmsClientToServer);
        serverSupportedCipherAlgorithmsServerToClient = new LinkedList<>(clientSupportedCipherAlgorithmsClientToServer);

        clientSupportedMacAlgorithmsClientToServer = new LinkedList<>();
        clientSupportedMacAlgorithmsClientToServer.add(MacAlgorithm.HMAC_SHA1);
        clientSupportedMacAlgorithmsServerToClient = new LinkedList<>(clientSupportedMacAlgorithmsClientToServer);
        serverSupportedMacAlgorithmsServerToClient = new LinkedList<>(clientSupportedMacAlgorithmsClientToServer);
        serverSupportedMacAlgorithmsClientToServer = new LinkedList<>(clientSupportedMacAlgorithmsClientToServer);

        clientSupportedCompressionAlgorithmsClientToServer = new LinkedList<>();
        clientSupportedCompressionAlgorithmsClientToServer.add(CompressionAlgorithm.NONE);
        clientSupportedCompressionAlgorithmsServerToClient = new LinkedList<>(
                clientSupportedCompressionAlgorithmsClientToServer);
        serverSupportedCompressionAlgorithmsServerToClient = new LinkedList<>(
                clientSupportedCompressionAlgorithmsClientToServer);
        serverSupportedCompressionAlgorithmsClientToServer = new LinkedList<>(
                clientSupportedCompressionAlgorithmsClientToServer);

        clientSupportedLanguagesClientToServer = new LinkedList<>();
        clientSupportedLanguagesServerToClient = new LinkedList<>(clientSupportedLanguagesClientToServer);
        serverSupportedLanguagesServerToClient = new LinkedList<>(clientSupportedLanguagesClientToServer);
        serverSupportedLanguagesClientToServer = new LinkedList<>(clientSupportedLanguagesClientToServer);

        clientFirstKeyExchangePacketFollows = false;
        serverFirstKeyExchangePacketFollows = false;

        clientReserved = 0;
        serverReserved = 0;

        authenticationMethod = AuthenticationMethod.PASSWORD;
        serviceName = "ssh-userauth";
        username = "sshattacker";
        password = "bydahirsch";
        localChannel = 1337;
        remoteChannel = 0;
        windowSize = Integer.MAX_VALUE;
        packetSize = Integer.MAX_VALUE;
        channelType = ChannelType.SESSION;
        channelRequestType = ChannelRequestType.EXEC;
        channelCommand = "nc -l -p 13370";
        replyWanted = 0;

        workflowTraceType = WorkflowTraceType.FULL;
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

    public int getLocalChannel() {
        return localChannel;
    }

    public void setLocalChannel(int localChannel) {
        this.localChannel = localChannel;
    }

    public int getWindowSize() {
        return windowSize;
    }

    public void setWindowSize(int windowSize) {
        this.windowSize = windowSize;
    }

    public int getPacketSize() {
        return packetSize;
    }

    public void setPacketSize(int packetSize) {
        this.packetSize = packetSize;
    }

    public ChannelType getChannelType() {
        return channelType;
    }

    public void setChannelType(ChannelType channelType) {
        this.channelType = channelType;
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

    public int getRemoteChannel() {
        return remoteChannel;
    }

    public void setRemoteChannel(int remoteChannel) {
        this.remoteChannel = remoteChannel;
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

}
