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
import de.rub.nds.sshattacker.core.constants.*;
import de.rub.nds.sshattacker.core.exceptions.ConfigurationException;
import de.rub.nds.sshattacker.core.protocol.authentication.message.*;
import de.rub.nds.sshattacker.core.protocol.connection.message.*;
import de.rub.nds.sshattacker.core.protocol.transport.message.*;
import de.rub.nds.sshattacker.core.workflow.WorkflowTrace;
import de.rub.nds.sshattacker.core.workflow.action.*;
import de.rub.nds.tlsattacker.transport.ConnectionEndType;
import java.util.ArrayList;
import java.util.List;

/** Create a WorkflowTace based on a Config instance. */
public class WorkflowConfigurationFactory {

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
            case AUTH_PASSWORD:
                return createAuthenticationWorkflowTrace(AuthenticationMethod.PASSWORD);
            case AUTH_KEYBOARD_INTERACTIVE:
                return createAuthenticationWorkflowTrace(AuthenticationMethod.KEYBOARD_INTERACTIVE);
            case FULL:
                return createFullWorkflowTrace();
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

    public WorkflowTrace createFullWorkflowTrace() {
        WorkflowTrace workflow = new WorkflowTrace();
        addTransportProtocolActions(workflow);
        addAuthenticationProtocolActions(workflow);
        addConnectionProtocolActions(workflow);
        return workflow;
    }

    private void addTransportProtocolInitActions(WorkflowTrace workflow) {
        AliasedConnection connection = getDefaultConnection();
        workflow.addSshActions(
                MessageActionFactory.createAction(
                        connection, ConnectionEndType.CLIENT, new VersionExchangeMessage()),
                MessageActionFactory.createAction(
                        connection, ConnectionEndType.SERVER, new VersionExchangeMessage()),
                new ChangePacketLayerAction(connection.getAlias(), PacketLayerType.BINARY_PACKET),
                MessageActionFactory.createAction(
                        connection, ConnectionEndType.CLIENT, new KeyExchangeInitMessage()),
                MessageActionFactory.createAction(
                        connection, ConnectionEndType.SERVER, new KeyExchangeInitMessage()));
    }

    private void addTransportProtocolActions(WorkflowTrace workflow) {
        AliasedConnection connection = getDefaultConnection();
        addTransportProtocolInitActions(workflow);
        workflow.addSshActions(new DynamicKeyExchangeAction(connection.getAlias()));
        workflow.addSshActions(
                MessageActionFactory.createAction(
                        connection, ConnectionEndType.CLIENT, new ServiceRequestMessage()),
                MessageActionFactory.createAction(
                        connection, ConnectionEndType.SERVER, new ServiceAcceptMessage()));
    }

    private void addTransportProtocolActions(KeyExchangeFlowType flowType, WorkflowTrace workflow) {
        AliasedConnection connection = getDefaultConnection();
        addTransportProtocolInitActions(workflow);
        workflow.addSshActions(createKeyExchangeActions(flowType, connection));
        workflow.addSshActions(
                MessageActionFactory.createAction(
                        connection, ConnectionEndType.CLIENT, new ServiceRequestMessage()),
                MessageActionFactory.createAction(
                        connection, ConnectionEndType.SERVER, new ServiceAcceptMessage()));
    }

    public List<SshAction> createKeyExchangeActions(
            KeyExchangeFlowType flowType, AliasedConnection connection) {
        List<SshAction> sshActions = new ArrayList<>();
        switch (flowType) {
            case DIFFIE_HELLMAN:
                sshActions.add(
                        MessageActionFactory.createAction(
                                connection,
                                ConnectionEndType.CLIENT,
                                new DhKeyExchangeInitMessage()));
                sshActions.add(
                        MessageActionFactory.createAction(
                                connection,
                                ConnectionEndType.SERVER,
                                new DhKeyExchangeReplyMessage(),
                                new NewKeysMessage()));
                break;
            case DIFFIE_HELLMAN_GROUP_EXCHANGE:
                sshActions.add(
                        MessageActionFactory.createAction(
                                connection,
                                ConnectionEndType.CLIENT,
                                new DhGexKeyExchangeRequestMessage(),
                                new NewKeysMessage()));
                sshActions.add(
                        MessageActionFactory.createAction(
                                connection,
                                ConnectionEndType.SERVER,
                                new DhGexKeyExchangeGroupMessage()));
                sshActions.add(
                        MessageActionFactory.createAction(
                                connection,
                                ConnectionEndType.CLIENT,
                                new DhGexKeyExchangeInitMessage()));
                sshActions.add(
                        MessageActionFactory.createAction(
                                connection,
                                ConnectionEndType.SERVER,
                                new DhGexKeyExchangeReplyMessage(),
                                new NewKeysMessage()));
                break;
            case ECDH:
                sshActions.add(
                        MessageActionFactory.createAction(
                                connection,
                                ConnectionEndType.CLIENT,
                                new EcdhKeyExchangeInitMessage()));
                sshActions.add(
                        MessageActionFactory.createAction(
                                connection,
                                ConnectionEndType.SERVER,
                                new EcdhKeyExchangeReplyMessage(),
                                new NewKeysMessage()));
                break;
            case RSA:
                sshActions.add(
                        MessageActionFactory.createAction(
                                connection,
                                ConnectionEndType.SERVER,
                                new RsaKeyExchangePubkeyMessage()));
                sshActions.add(
                        MessageActionFactory.createAction(
                                connection,
                                ConnectionEndType.CLIENT,
                                new RsaKeyExchangeSecretMessage()));
                sshActions.add(
                        MessageActionFactory.createAction(
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
                MessageActionFactory.createAction(
                        connection, ConnectionEndType.CLIENT, new NewKeysMessage()));
        sshActions.add(new ActivateEncryptionAction(connection.getAlias()));
        return sshActions;
    }

    private void addAuthenticationProtocolActions(WorkflowTrace workflow) {
        this.addAuthenticationProtocolActions(AuthenticationMethod.KEYBOARD_INTERACTIVE, workflow);
    }

    private void addAuthenticationProtocolActions(
            AuthenticationMethod method, WorkflowTrace workflow) {
        AliasedConnection connection = getDefaultConnection();
        //noinspection SwitchStatementWithTooFewBranches
        switch (method) {
            case PASSWORD:
                workflow.addSshActions(
                        MessageActionFactory.createAction(
                                connection,
                                ConnectionEndType.CLIENT,
                                new UserAuthPasswordMessage()),
                        MessageActionFactory.createAction(
                                connection,
                                ConnectionEndType.SERVER,
                                new UserAuthSuccessMessage()));
                break;
            case KEYBOARD_INTERACTIVE:
                workflow.addSshActions(
                        MessageActionFactory.createAction(
                                connection,
                                ConnectionEndType.CLIENT,
                                new UserAuthKeyboardInteractiveMessage()),
                        MessageActionFactory.createAction(
                                connection,
                                ConnectionEndType.SERVER,
                                new UserAuthInfoRequestMessage()),
                        MessageActionFactory.createAction(
                                connection,
                                ConnectionEndType.CLIENT,
                                new UserAuthInfoResponseMessage()),
                        MessageActionFactory.createAction(
                                connection,
                                ConnectionEndType.SERVER,
                                new UserAuthInfoRequestMessage()),
                        MessageActionFactory.createAction(
                                connection,
                                ConnectionEndType.CLIENT,
                                new UserAuthInfoResponseMessage()),
                        MessageActionFactory.createAction(
                                connection,
                                ConnectionEndType.CLIENT,
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
                MessageActionFactory.createAction(
                        connection, ConnectionEndType.CLIENT, new ChannelOpenMessage(1337)),
                MessageActionFactory.createAction(
                        connection, ConnectionEndType.SERVER, new ChannelOpenConfirmationMessage()),
                MessageActionFactory.createAction(
                        connection, ConnectionEndType.CLIENT, new ChannelOpenMessage(1338)),
                MessageActionFactory.createAction(
                        connection, ConnectionEndType.SERVER, new ChannelOpenConfirmationMessage()),
                MessageActionFactory.createAction(
                        connection, ConnectionEndType.CLIENT, new ChannelRequestExecMessage(1337)),
                MessageActionFactory.createAction(
                        connection, ConnectionEndType.SERVER, new ChannelWindowAdjustMessage()),
                MessageActionFactory.createAction(
                        connection, ConnectionEndType.CLIENT, new ChannelWindowAdjustMessage(1337)),
                MessageActionFactory.createAction(
                        connection, ConnectionEndType.CLIENT, new ChannelEofMessage(1337)),
                MessageActionFactory.createAction(
                        connection, ConnectionEndType.CLIENT, new ChannelDataMessage(1337)),
                MessageActionFactory.createAction(
                        connection, ConnectionEndType.CLIENT, new ChannelExtendedDataMessage(1337)),
                MessageActionFactory.createAction(
                        connection, ConnectionEndType.CLIENT, new ChannelCloseMessage(1337)),
                MessageActionFactory.createAction(
                        connection, ConnectionEndType.SERVER, new ChannelCloseMessage()));
    }
}
