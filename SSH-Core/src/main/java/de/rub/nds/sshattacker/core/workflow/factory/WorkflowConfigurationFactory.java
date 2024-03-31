/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.workflow.factory;

import de.rub.nds.sshattacker.core.config.Config;
import de.rub.nds.sshattacker.core.connection.AliasedConnection;
import de.rub.nds.sshattacker.core.constants.AuthenticationMethod;
import de.rub.nds.sshattacker.core.constants.KeyExchangeFlowType;
import de.rub.nds.sshattacker.core.constants.PacketLayerType;
import de.rub.nds.sshattacker.core.constants.RunningModeType;
import de.rub.nds.sshattacker.core.exceptions.ConfigurationException;
import de.rub.nds.sshattacker.core.protocol.authentication.message.*;
import de.rub.nds.sshattacker.core.protocol.connection.message.*;
import de.rub.nds.sshattacker.core.protocol.ssh1.client.message.ClientSessionKeyMessage;
import de.rub.nds.sshattacker.core.protocol.ssh1.general.message.VersionExchangeMessageSSHV1;
import de.rub.nds.sshattacker.core.protocol.ssh1.server.message.ServerPublicKeyMessage;
import de.rub.nds.sshattacker.core.protocol.transport.message.*;
import de.rub.nds.sshattacker.core.workflow.WorkflowTrace;
import de.rub.nds.sshattacker.core.workflow.action.*;
import de.rub.nds.tlsattacker.transport.ConnectionEndType;
import java.util.ArrayList;
import java.util.List;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/** Create a WorkflowTrace based on a Config instance. */
public class WorkflowConfigurationFactory {

    private static final Logger LOGGER = LogManager.getLogger();

    protected final Config config;
    private RunningModeType mode;

    public WorkflowConfigurationFactory(Config config) {
        super();
        this.config = config;
    }

    public WorkflowTrace createWorkflowTrace(
            WorkflowTraceType workflowTraceType, RunningModeType runningMode) {
        mode = runningMode;
        switch (workflowTraceType) {
            case KEX_INIT_ONLY:
                return createInitKeyExchangeWorkflowTrace();
            case KEX_SSH1_ONLY:
                return createSSH1KeyExchangeWorkflowTrace();
            case KEX_DH:
                return createKeyExchangeWorkflowTrace(KeyExchangeFlowType.DIFFIE_HELLMAN);
            case KEX_DH_GEX:
                return createKeyExchangeWorkflowTrace(
                        KeyExchangeFlowType.DIFFIE_HELLMAN_GROUP_EXCHANGE);
            case KEX_ECDH:
                return createKeyExchangeWorkflowTrace(KeyExchangeFlowType.ECDH);
            case KEX_RSA:
                return createKeyExchangeWorkflowTrace(KeyExchangeFlowType.RSA);
            case KEX_HYBRID:
                return createKeyExchangeWorkflowTrace(KeyExchangeFlowType.HYBRID);
            case KEX_DYNAMIC:
                return createDynamicKeyExchangeWorkflowTrace();
            case AUTH_NONE:
                return createAuthenticationWorkflowTrace(AuthenticationMethod.NONE);
            case AUTH_PASSWORD:
                return createAuthenticationWorkflowTrace(AuthenticationMethod.PASSWORD);
            case AUTH_PUBLICKEY:
                return createAuthenticationWorkflowTrace(AuthenticationMethod.PUBLICKEY);
            case AUTH_KEYBOARD_INTERACTIVE:
                return createAuthenticationWorkflowTrace(AuthenticationMethod.KEYBOARD_INTERACTIVE);
            case AUTH_DYNAMIC:
                return createDynamicAuthenticationWorkflowTrace();
            case FULL:
                return createFullWorkflowTrace();
            case MITM:
                return createSimpleMitmProxyWorkflow();
            case SSH1:
                return createSSHv1Workflow();
            default:
                throw new ConfigurationException(
                        "Unable to create workflow trace - Unknown WorkflowTraceType: "
                                + workflowTraceType.name());
        }
    }

    private AliasedConnection getDefaultConnection() {
        if (mode == null) {
            throw new ConfigurationException("Running mode not set, can't configure workflow");
        } else {
            switch (mode) {
                case CLIENT:
                    return config.getDefaultClientConnection();
                case SERVER:
                    return config.getDefaultServerConnection();
                default:
                    throw new ConfigurationException(
                            "This workflow can only be configured for"
                                    + " modes CLIENT and SERVER, but actual mode was "
                                    + mode);
            }
        }
    }

    public WorkflowTrace createSSHv1Workflow() {
        WorkflowTrace workflow = new WorkflowTrace();
        addSSHV1Packates(workflow);
        return workflow;
    }

    public WorkflowTrace createInitKeyExchangeWorkflowTrace() {
        WorkflowTrace workflow = new WorkflowTrace();
        addTransportProtocolInitActions(workflow);
        return workflow;
    }

    public WorkflowTrace createSSH1KeyExchangeWorkflowTrace() {
        WorkflowTrace workflow = new WorkflowTrace();
        addSSH1KexProtocolInitActions(workflow);
        return workflow;
    }

    public WorkflowTrace createKeyExchangeWorkflowTrace(KeyExchangeFlowType flowType) {
        WorkflowTrace workflow = new WorkflowTrace();
        addTransportProtocolActions(flowType, workflow);
        return workflow;
    }

    public WorkflowTrace createDynamicKeyExchangeWorkflowTrace() {
        WorkflowTrace workflow = new WorkflowTrace();
        addTransportProtocolActions(workflow);
        return workflow;
    }

    public WorkflowTrace createAuthenticationWorkflowTrace(AuthenticationMethod method) {
        WorkflowTrace workflow = new WorkflowTrace();
        addTransportProtocolActions(workflow);
        addAuthenticationProtocolActions(method, workflow);
        return workflow;
    }

    /**
     * Create a workflow trace with that includes user authentication.
     *
     * <p>The authentication method is selected dynamically, based on the configuration.
     *
     * @return a new workflow trace
     */
    public WorkflowTrace createDynamicAuthenticationWorkflowTrace() {
        WorkflowTrace workflow = new WorkflowTrace();
        addTransportProtocolActions(workflow);
        addAuthenticationProtocolActions(workflow);
        return workflow;
    }

    public WorkflowTrace createFullWorkflowTrace() {
        WorkflowTrace workflow = new WorkflowTrace();
        addTransportProtocolActions(workflow);
        addAuthenticationProtocolActions(workflow);
        addConnectionProtocolActions(workflow);
        return workflow;
    }

    private void addSSHV1Packates(WorkflowTrace workflow) {
        AliasedConnection connection = getDefaultConnection();
        workflow.addSshActions(
                SshActionFactory.createMessageAction(
                        connection, ConnectionEndType.SERVER, new VersionExchangeMessageSSHV1()),
                SshActionFactory.createMessageAction(
                        connection, ConnectionEndType.CLIENT, new VersionExchangeMessageSSHV1()),
                new ChangePacketLayerAction(connection.getAlias(), PacketLayerType.BINARY_PACKET),
                SshActionFactory.createMessageAction(
                        connection, ConnectionEndType.SERVER, new ServerPublicKeyMessage()),
                SshActionFactory.createMessageAction(
                        connection, ConnectionEndType.CLIENT, new ServerPublicKeyMessage()));
    }

    private void addTransportProtocolInitActions(WorkflowTrace workflow) {
        if (mode == RunningModeType.MITM) {
            AliasedConnection inboundConnection = config.getDefaultServerConnection();
            AliasedConnection outboundConnection = config.getDefaultClientConnection();
            workflow.addSshActions(
                    SshActionFactory.createForwardAction(
                            inboundConnection,
                            outboundConnection,
                            ConnectionEndType.SERVER,
                            new VersionExchangeMessage()),
                    SshActionFactory.createForwardAction(
                            inboundConnection,
                            outboundConnection,
                            ConnectionEndType.CLIENT,
                            new VersionExchangeMessage()),
                    new ChangePacketLayerAction(
                            inboundConnection.getAlias(), PacketLayerType.BINARY_PACKET),
                    new ChangePacketLayerAction(
                            outboundConnection.getAlias(), PacketLayerType.BINARY_PACKET),
                    SshActionFactory.createForwardAction(
                            inboundConnection,
                            outboundConnection,
                            ConnectionEndType.CLIENT,
                            new KeyExchangeInitMessage()),
                    SshActionFactory.createForwardAction(
                            inboundConnection,
                            outboundConnection,
                            ConnectionEndType.SERVER,
                            new KeyExchangeInitMessage()));
        } else {
            AliasedConnection connection = getDefaultConnection();
            workflow.addSshActions(
                    SshActionFactory.createMessageAction(
                            connection, ConnectionEndType.CLIENT, new VersionExchangeMessage()),
                    SshActionFactory.createMessageAction(
                            connection, ConnectionEndType.SERVER, new VersionExchangeMessage()),
                    new ChangePacketLayerAction(
                            connection.getAlias(), PacketLayerType.BINARY_PACKET),
                    SshActionFactory.createMessageAction(
                            connection, ConnectionEndType.CLIENT, new KeyExchangeInitMessage()),
                    SshActionFactory.createMessageAction(
                            connection, ConnectionEndType.SERVER, new KeyExchangeInitMessage()));
        }
    }

    private void addSSH1KexProtocolInitActions(WorkflowTrace workflow) {
        if (mode == RunningModeType.MITM) {
            AliasedConnection inboundConnection = config.getDefaultServerConnection();
            AliasedConnection outboundConnection = config.getDefaultClientConnection();
            workflow.addSshActions(
                    SshActionFactory.createForwardAction(
                            inboundConnection,
                            outboundConnection,
                            ConnectionEndType.SERVER,
                            new VersionExchangeMessageSSHV1()),
                    SshActionFactory.createForwardAction(
                            inboundConnection,
                            outboundConnection,
                            ConnectionEndType.CLIENT,
                            new VersionExchangeMessageSSHV1()),
                    new ChangePacketLayerAction(
                            inboundConnection.getAlias(), PacketLayerType.BINARY_PACKET),
                    new ChangePacketLayerAction(
                            outboundConnection.getAlias(), PacketLayerType.BINARY_PACKET),
                    SshActionFactory.createForwardAction(
                            inboundConnection,
                            outboundConnection,
                            ConnectionEndType.CLIENT,
                            new ServerPublicKeyMessage()),
                    SshActionFactory.createForwardAction(
                            inboundConnection,
                            outboundConnection,
                            ConnectionEndType.SERVER,
                            new ClientSessionKeyMessage()));
        } else {
            AliasedConnection connection = getDefaultConnection();
            workflow.addSshActions(
                    SshActionFactory.createMessageAction(
                            connection,
                            ConnectionEndType.SERVER,
                            new VersionExchangeMessageSSHV1()),
                    SshActionFactory.createMessageAction(
                            connection,
                            ConnectionEndType.CLIENT,
                            new VersionExchangeMessageSSHV1()),
                    new ChangePacketLayerAction(
                            connection.getAlias(), PacketLayerType.BINARY_PACKET));
        }
    }

    private void addTransportProtocolActions(WorkflowTrace workflow) {
        if (mode == RunningModeType.MITM) {
            addTransportProtocolInitActions(workflow);
            workflow.addSshActions(
                    new DynamicKeyExchangeAction(config.getDefaultServerConnection().getAlias()));
            workflow.addSshActions(
                    new DynamicKeyExchangeAction(config.getDefaultClientConnection().getAlias()));
            workflow.addSshActions(
                    SshActionFactory.createProxyFilterMessagesAction(
                            config.getDefaultServerConnection(),
                            config.getDefaultClientConnection(),
                            ConnectionEndType.CLIENT,
                            new ServiceRequestMessage()));
            workflow.addSshActions(
                    SshActionFactory.createProxyFilterMessagesAction(
                            config.getDefaultServerConnection(),
                            config.getDefaultClientConnection(),
                            ConnectionEndType.SERVER,
                            new ServiceAcceptMessage()));
        } else {
            AliasedConnection connection = getDefaultConnection();
            addTransportProtocolInitActions(workflow);
            workflow.addSshActions(new DynamicKeyExchangeAction(connection.getAlias()));
            workflow.addSshActions(new DynamicExtensionNegotiationAction(connection.getAlias()));
            workflow.addSshActions(
                    SshActionFactory.createMessageAction(
                            connection, ConnectionEndType.CLIENT, new ServiceRequestMessage()),
                    SshActionFactory.createMessageAction(
                            connection, ConnectionEndType.SERVER, new ServiceAcceptMessage()));
        }
    }

    private void addTransportProtocolActions(KeyExchangeFlowType flowType, WorkflowTrace workflow) {
        if (mode == RunningModeType.MITM) {
            addTransportProtocolInitActions(workflow);
            workflow.addSshActions(createKeyExchangeActionsMitm(flowType));
        } else {
            AliasedConnection connection = getDefaultConnection();
            addTransportProtocolInitActions(workflow);
            workflow.addSshActions(createKeyExchangeActions(flowType, connection));
            workflow.addSshActions(new DynamicExtensionNegotiationAction(connection.getAlias()));
            workflow.addSshActions(
                    SshActionFactory.createMessageAction(
                            connection, ConnectionEndType.CLIENT, new ServiceRequestMessage()),
                    SshActionFactory.createMessageAction(
                            connection, ConnectionEndType.SERVER, new ServiceAcceptMessage()));
        }
    }

    public List<SshAction> createKeyExchangeActionsMitm(KeyExchangeFlowType flowType) {
        List<SshAction> sshActions = new ArrayList<>();
        if (mode == RunningModeType.MITM) {
            // KeyExchange on server side
            sshActions.addAll(
                    createKeyExchangeActions(flowType, config.getDefaultClientConnection()));
            // KeyExchange on client side
            sshActions.addAll(
                    createKeyExchangeActions(flowType, config.getDefaultServerConnection()));
        }
        return sshActions;
    }

    public static List<SshAction> createKeyExchangeActions(
            KeyExchangeFlowType flowType, AliasedConnection connection) {
        List<SshAction> sshActions = new ArrayList<>();
        if (flowType == null) {
            // This may happen if the key exchange algorithm is `ext-info-s` or
            // `ext-info-c` [RFC 8308], since they do not have an associated
            // flow type.
            //
            // This case is not covered by the default case of the `switch`
            // statement below, as per the Java Language Specification (JLS)
            // §14.11:
            //
            //    When the switch statement is executed, first the Expression
            //    is evaluated. If the Expression evaluates to `null`, a
            //    `NullPointerException` is thrown and the entire switch
            //    statement completes abruptly for that reason.
            //
            // See this for details:
            // http://docs.oracle.com/javase/specs/jls/se8/html/jls-14.html#jls-14.11
            throw new ConfigurationException(
                    "Unable to add key exchange actions to workflow trace - key exchange algorithm has no flow type!");
        }

        switch (flowType) {
            case HYBRID:
                sshActions.add(
                        SshActionFactory.createMessageAction(
                                connection,
                                ConnectionEndType.CLIENT,
                                new HybridKeyExchangeInitMessage()));
                sshActions.add(
                        SshActionFactory.createMessageAction(
                                connection,
                                ConnectionEndType.SERVER,
                                new HybridKeyExchangeReplyMessage(),
                                new NewKeysMessage()));
                break;
            case DIFFIE_HELLMAN:
                sshActions.add(
                        SshActionFactory.createMessageAction(
                                connection,
                                ConnectionEndType.CLIENT,
                                new DhKeyExchangeInitMessage()));
                sshActions.add(
                        SshActionFactory.createMessageAction(
                                connection,
                                ConnectionEndType.SERVER,
                                new DhKeyExchangeReplyMessage(),
                                new NewKeysMessage()));
                break;
            case DIFFIE_HELLMAN_GROUP_EXCHANGE:
                sshActions.add(
                        SshActionFactory.createMessageAction(
                                connection,
                                ConnectionEndType.CLIENT,
                                new DhGexKeyExchangeRequestMessage()));
                sshActions.add(
                        SshActionFactory.createMessageAction(
                                connection,
                                ConnectionEndType.SERVER,
                                new DhGexKeyExchangeGroupMessage()));
                sshActions.add(
                        SshActionFactory.createMessageAction(
                                connection,
                                ConnectionEndType.CLIENT,
                                new DhGexKeyExchangeInitMessage()));
                sshActions.add(
                        SshActionFactory.createMessageAction(
                                connection,
                                ConnectionEndType.SERVER,
                                new DhGexKeyExchangeReplyMessage(),
                                new NewKeysMessage()));
                break;
            case ECDH:
                sshActions.add(
                        SshActionFactory.createMessageAction(
                                connection,
                                ConnectionEndType.CLIENT,
                                new EcdhKeyExchangeInitMessage()));
                sshActions.add(
                        SshActionFactory.createMessageAction(
                                connection,
                                ConnectionEndType.SERVER,
                                new EcdhKeyExchangeReplyMessage(),
                                new NewKeysMessage()));
                break;
            case RSA:
                sshActions.add(
                        SshActionFactory.createMessageAction(
                                connection,
                                ConnectionEndType.SERVER,
                                new RsaKeyExchangePubkeyMessage()));
                sshActions.add(
                        SshActionFactory.createMessageAction(
                                connection,
                                ConnectionEndType.CLIENT,
                                new RsaKeyExchangeSecretMessage()));
                sshActions.add(
                        SshActionFactory.createMessageAction(
                                connection,
                                ConnectionEndType.SERVER,
                                new RsaKeyExchangeDoneMessage(),
                                new NewKeysMessage()));
                break;
            default:
                throw new ConfigurationException(
                        "Unable to add key exchange actions to workflow trace - unknown or unsupported key exchange flow type: "
                                + flowType);
        }
        sshActions.add(
                SshActionFactory.createMessageAction(
                        connection, ConnectionEndType.CLIENT, new NewKeysMessage()));
        return sshActions;
    }

    /**
     * Add authentication protocol actions using the configured authentication method to an existing
     * workflow.
     *
     * @param workflow the workflow trace to add actions to
     */
    public void addAuthenticationProtocolActions(WorkflowTrace workflow) {
        addAuthenticationProtocolActions(config.getAuthenticationMethod(), workflow);
    }

    /**
     * Add authentication protocol actions with the specified authentication method to an existing
     * workflow.
     *
     * @param method the authentication method to use
     * @param workflow the workflow trace to add actions to
     */
    public void addAuthenticationProtocolActions(
            AuthenticationMethod method, WorkflowTrace workflow) {
        AliasedConnection connection = getDefaultConnection();
        switch (method) {
            case NONE:
                workflow.addSshActions(
                        SshActionFactory.createMessageAction(
                                connection, ConnectionEndType.CLIENT, new UserAuthNoneMessage()),
                        SshActionFactory.createMessageAction(
                                connection,
                                ConnectionEndType.SERVER,
                                new UserAuthSuccessMessage()));
                break;
            case PASSWORD:
                workflow.addSshActions(
                        SshActionFactory.createMessageAction(
                                connection,
                                ConnectionEndType.CLIENT,
                                new UserAuthPasswordMessage()),
                        SshActionFactory.createMessageAction(
                                connection,
                                ConnectionEndType.SERVER,
                                new UserAuthSuccessMessage()));
                break;
            case PUBLICKEY:
                workflow.addSshActions(
                        SshActionFactory.createMessageAction(
                                connection, ConnectionEndType.CLIENT, new UserAuthPubkeyMessage()),
                        SshActionFactory.createMessageAction(
                                connection,
                                ConnectionEndType.SERVER,
                                new UserAuthSuccessMessage()));
                break;
            case KEYBOARD_INTERACTIVE:
                workflow.addSshActions(
                        SshActionFactory.createMessageAction(
                                connection,
                                ConnectionEndType.CLIENT,
                                new UserAuthKeyboardInteractiveMessage()),
                        SshActionFactory.createMessageAction(
                                connection,
                                ConnectionEndType.SERVER,
                                new UserAuthInfoRequestMessage()),
                        SshActionFactory.createMessageAction(
                                connection,
                                ConnectionEndType.CLIENT,
                                new UserAuthInfoResponseMessage()),
                        SshActionFactory.createMessageAction(
                                connection,
                                ConnectionEndType.SERVER,
                                new UserAuthInfoRequestMessage()),
                        SshActionFactory.createMessageAction(
                                connection,
                                ConnectionEndType.CLIENT,
                                new UserAuthInfoResponseMessage()),
                        SshActionFactory.createMessageAction(
                                connection,
                                ConnectionEndType.SERVER,
                                new UserAuthSuccessMessage()));
                break;
            case HOST_BASED:
                workflow.addSshActions(
                        SshActionFactory.createMessageAction(
                                connection,
                                ConnectionEndType.CLIENT,
                                new UserAuthHostbasedMessage()),
                        SshActionFactory.createMessageAction(
                                connection,
                                ConnectionEndType.SERVER,
                                new UserAuthSuccessMessage()));
                break;
            default:
                throw new ConfigurationException(
                        "Unable to add authentication actions to workflow trace - unknown or unsupported authentication method: "
                                + method);
        }
        workflow.addSshActions(new DynamicDelayCompressionAction(connection.getAlias()));
    }

    /**
     * Add connections protocol actions to an existing workflow.
     *
     * @param workflow the workflow trace to add actions to
     */
    public void addConnectionProtocolActions(WorkflowTrace workflow) {
        AliasedConnection connection = getDefaultConnection();
        workflow.addSshActions(
                SshActionFactory.createMessageAction(
                        connection, ConnectionEndType.CLIENT, new ChannelOpenSessionMessage()),
                SshActionFactory.createMessageAction(
                        connection, ConnectionEndType.SERVER, new ChannelOpenConfirmationMessage()),
                SshActionFactory.createMessageAction(
                        connection,
                        ConnectionEndType.CLIENT,
                        new ChannelRequestPtyMessage(),
                        new ChannelRequestEnvMessage(),
                        new ChannelRequestEnvMessage(),
                        new ChannelRequestEnvMessage(),
                        new ChannelRequestEnvMessage()),
                SshActionFactory.createMessageAction(
                        connection, ConnectionEndType.SERVER, new ChannelSuccessMessage()),
                SshActionFactory.createMessageAction(
                        connection, ConnectionEndType.SERVER, new ChannelSuccessMessage()),
                SshActionFactory.createMessageAction(
                        connection, ConnectionEndType.CLIENT, new ChannelRequestEnvMessage()));
    }

    private WorkflowTrace createSimpleMitmProxyWorkflow() {
        WorkflowTrace workflow = new WorkflowTrace();

        if (mode != RunningModeType.MITM) {
            throw new ConfigurationException(
                    "This workflow trace can only be created when running"
                            + " in MITM mode. Actual mode: "
                            + mode);
        }

        AliasedConnection inboundConnection = config.getDefaultServerConnection();
        AliasedConnection outboundConnection = config.getDefaultClientConnection();

        if (outboundConnection == null || inboundConnection == null) {
            throw new ConfigurationException("Could not find both necessary connection ends");
        }

        LOGGER.debug("Building mitm trace for: {}, {}", inboundConnection, outboundConnection);
        addTransportProtocolActions(workflow);
        // The following is run in a loop in SSH-MITM.
        workflow.addSshActions(
                SshActionFactory.createProxyFilterMessagesAction(
                        inboundConnection, outboundConnection, ConnectionEndType.SERVER));
        workflow.addSshActions(
                SshActionFactory.createProxyFilterMessagesAction(
                        inboundConnection, outboundConnection, ConnectionEndType.CLIENT));

        return workflow;
    }
}
