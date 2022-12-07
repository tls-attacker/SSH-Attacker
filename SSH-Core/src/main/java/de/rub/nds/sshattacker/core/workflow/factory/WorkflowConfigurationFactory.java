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
import de.rub.nds.sshattacker.core.protocol.transport.message.*;
import de.rub.nds.sshattacker.core.workflow.WorkflowTrace;
import de.rub.nds.sshattacker.core.workflow.action.ChangePacketLayerAction;
import de.rub.nds.sshattacker.core.workflow.action.DynamicKeyExchangeAction;
import de.rub.nds.sshattacker.core.workflow.action.SshAction;
import de.rub.nds.tlsattacker.transport.ConnectionEndType;
import java.util.ArrayList;
import java.util.List;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/** Create a WorkflowTace based on a Config instance. */
public class WorkflowConfigurationFactory {

    private static final Logger LOGGER = LogManager.getLogger();

    protected final Config config;
    private RunningModeType mode;

    public WorkflowConfigurationFactory(Config config) {
        this.config = config;
    }

    public WorkflowTrace createWorkflowTrace(
            WorkflowTraceType workflowTraceType, RunningModeType runningMode) {
        this.mode = runningMode;
        switch (workflowTraceType) {
            case KEX_INIT_ONLY:
                return createInitKeyExchangeWorkflowTrace();
            case KEX_DH:
                return createKeyExchangeWorkflowTrace(KeyExchangeFlowType.DIFFIE_HELLMAN);
            case KEX_DH_GEX:
                return createKeyExchangeWorkflowTrace(
                        KeyExchangeFlowType.DIFFIE_HELLMAN_GROUP_EXCHANGE);
            case KEX_ECDH:
                return createKeyExchangeWorkflowTrace(KeyExchangeFlowType.ECDH);
            case KEX_RSA:
                return createKeyExchangeWorkflowTrace(KeyExchangeFlowType.RSA);
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

    public WorkflowTrace createInitKeyExchangeWorkflowTrace() {
        WorkflowTrace workflow = new WorkflowTrace();
        addTransportProtocolInitActions(workflow);
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

    private void addTransportProtocolInitActions(WorkflowTrace workflow) {
        if (this.mode == RunningModeType.MITM) {
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

    private void addTransportProtocolActions(WorkflowTrace workflow) {
        AliasedConnection connection = getDefaultConnection();
        addTransportProtocolInitActions(workflow);
        workflow.addSshActions(new DynamicKeyExchangeAction(connection.getAlias()));
        workflow.addSshActions(
                SshActionFactory.createMessageAction(
                        connection, ConnectionEndType.CLIENT, new ServiceRequestMessage()),
                SshActionFactory.createMessageAction(
                        connection, ConnectionEndType.SERVER, new ServiceAcceptMessage()));
    }

    private void addTransportProtocolActions(KeyExchangeFlowType flowType, WorkflowTrace workflow) {
        AliasedConnection connection = getDefaultConnection();
        addTransportProtocolInitActions(workflow);
        workflow.addSshActions(createKeyExchangeActions(flowType, connection));
        workflow.addSshActions(
                SshActionFactory.createMessageAction(
                        connection, ConnectionEndType.CLIENT, new ServiceRequestMessage()),
                SshActionFactory.createMessageAction(
                        connection, ConnectionEndType.SERVER, new ServiceAcceptMessage()));
    }

    public List<SshAction> createKeyExchangeActions(
            KeyExchangeFlowType flowType, AliasedConnection connection) {
        List<SshAction> sshActions = new ArrayList<>();
        switch (flowType) {
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
                                new DhGexKeyExchangeRequestMessage(),
                                new NewKeysMessage()));
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

    private void addAuthenticationProtocolActions(WorkflowTrace workflow) {
        this.addAuthenticationProtocolActions(config.getAuthenticationMethod(), workflow);
    }

    private void addAuthenticationProtocolActions(
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
    }

    private void addConnectionProtocolActions(WorkflowTrace workflow) {
        AliasedConnection connection = getDefaultConnection();
        workflow.addSshActions(
                SshActionFactory.createMessageAction(
                        connection, ConnectionEndType.CLIENT, new ChannelOpenMessage()),
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

        // client -> mitm
        String clientToMitmAlias = inboundConnection.getAlias();
        // mitm -> server
        String mitmToServerAlias = outboundConnection.getAlias();

        LOGGER.debug("Building mitm trace for: " + inboundConnection + ", " + outboundConnection);
        addTransportProtocolInitActions(workflow);
        // KeyExchange on server side
        workflow.addSshActions(
                createKeyExchangeActions(KeyExchangeFlowType.ECDH, outboundConnection));
        // KeyExchange on client side
        workflow.addSshActions(
                createKeyExchangeActions(KeyExchangeFlowType.ECDH, inboundConnection));
        workflow.addSshActions(
                SshActionFactory.createProxyFilterMessagesAction(
                        inboundConnection,
                        outboundConnection,
                        ConnectionEndType.CLIENT,
                        new ServiceRequestMessage()));
        workflow.addSshActions(
                SshActionFactory.createProxyFilterMessagesAction(
                        inboundConnection,
                        outboundConnection,
                        ConnectionEndType.SERVER,
                        new ServiceAcceptMessage()));

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
