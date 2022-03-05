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
import de.rub.nds.sshattacker.core.protocol.authentication.message.UserAuthPasswordMessage;
import de.rub.nds.sshattacker.core.protocol.authentication.message.UserAuthSuccessMessage;
import de.rub.nds.sshattacker.core.protocol.common.ProtocolMessage;
import de.rub.nds.sshattacker.core.protocol.connection.message.*;
import de.rub.nds.sshattacker.core.protocol.transport.message.*;
import de.rub.nds.sshattacker.core.protocol.util.AlgorithmPicker;
import de.rub.nds.sshattacker.core.workflow.WorkflowTrace;
import de.rub.nds.sshattacker.core.workflow.action.*;
import de.rub.nds.tlsattacker.transport.ConnectionEndType;
import java.util.ArrayList;
import java.util.LinkedList;
import java.util.List;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/** Create a WorkflowTace based on a Config instance. */
public class WorkflowConfigurationFactory {

    private static final Logger LOGGER = LogManager.getLogger();

    protected final Config config;
    private RunningModeType mode;
    private WorkflowTraceType workflowTraceType;

    public WorkflowConfigurationFactory(Config config) {
        this.config = config;
    }

    public WorkflowTrace createWorkflowTrace(
            WorkflowTraceType workflowTraceType, RunningModeType runningMode) {
        this.workflowTraceType = workflowTraceType;
        this.mode = runningMode;
        switch (workflowTraceType) {
            case KEYEXCHANGE:
                return createKeyExchangeWorkflowTrace();
            case AUTHPASSWORD:
                return createAuthenticationPasswordWorkflowTrace();
            case FULL:
                return createFullWorkflowTrace();
            case DYNAMIC_KEYEXCHANGE:
                // TODO Implement dynamic workflow
            case DYNAMIC_AUTHPASSWORD:
            case DYNAMIC_FULL:
            default:
                throw new ConfigurationException(
                        "Unknown WorkflowTraceType" + workflowTraceType.name());
        }
    }

    private AliasedConnection getConnection() {
        AliasedConnection con = null;
        // ToDo because of implementation in WorkflowNormalizer, change after runningModeDelegate is
        // implemented
        if (null == mode) {
            mode = RunningModeType.CLIENT;
        }
        if (mode == null) {
            throw new ConfigurationException("Running mode not set, can't configure workflow");
        } else {
            switch (mode) {
                case CLIENT:
                    con = config.getDefaultClientConnection().getCopy();
                    break;
                case SERVER:
                    con = config.getDefaultServerConnection().getCopy();
                    break;
                default:
                    throw new ConfigurationException(
                            "This workflow can only be configured for"
                                    + " modes CLIENT and SERVER, but actual mode was "
                                    + mode);
            }
        }
        return con;
    }

    public WorkflowTrace createKeyExchangeWorkflowTrace() {
        WorkflowTrace workflow = startKeyExchangeWorkflowTrace();
        KeyExchangeAlgorithm choosenAlgorithm =
                AlgorithmPicker.pickAlgorithm(
                                config.getClientSupportedKeyExchangeAlgorithms(),
                                config.getServerSupportedKeyExchangeAlgorithms())
                        .orElse(null);
        workflow.addSshActions(this.createKeyExchangeActions(choosenAlgorithm));
        return workflow;
    }

    public WorkflowTrace createAuthenticationPasswordWorkflowTrace() {
        WorkflowTrace workflow = createKeyExchangeWorkflowTrace();
        workflow.addSshActions(createAuthPasswordActions());
        return workflow;
    }

    public WorkflowTrace createFullWorkflowTrace() {
        WorkflowTrace workflow = createAuthenticationPasswordWorkflowTrace();
        workflow.addSshActions(createConnectionProtocolActions());
        return workflow;
    }

    public WorkflowTrace startKeyExchangeWorkflowTrace() {
        WorkflowTrace workflow = new WorkflowTrace();
        workflow.setDirty(true);
        workflow.addSshAction(
                MessageActionFactory.createAction(
                        config,
                        getConnection(),
                        ConnectionEndType.CLIENT,
                        new VersionExchangeMessage()));
        workflow.addSshAction(
                MessageActionFactory.createAction(
                        config,
                        getConnection(),
                        ConnectionEndType.SERVER,
                        new VersionExchangeMessage()));
        workflow.addSshAction(new ChangePacketLayerAction(PacketLayerType.BINARY_PACKET));
        workflow.addSshAction(
                MessageActionFactory.createAction(
                        config,
                        getConnection(),
                        ConnectionEndType.CLIENT,
                        new KeyExchangeInitMessage()));
        workflow.addSshAction(
                MessageActionFactory.createAction(
                        config,
                        getConnection(),
                        ConnectionEndType.SERVER,
                        new KeyExchangeInitMessage()));
        return workflow;
    }

    public List<SshAction> createKeyExchangeActions(KeyExchangeAlgorithm choosenAlgorithm) {
        List<SshAction> sshActions = new LinkedList<>();
        KeyExchangeFlowType choosenKeyExchangeFlowType = choosenAlgorithm.getFlowType();
        switch (choosenKeyExchangeFlowType) {
            case DIFFIE_HELLMAN:
                sshActions.add(
                        MessageActionFactory.createAction(
                                config,
                                getConnection(),
                                ConnectionEndType.CLIENT,
                                new DhKeyExchangeInitMessage()));
                List<ProtocolMessage<?>> DhReplyandNewKeysMessage =
                        new ArrayList<ProtocolMessage<?>>();
                DhReplyandNewKeysMessage.add(new DhKeyExchangeReplyMessage());
                DhReplyandNewKeysMessage.add(new NewKeysMessage());
                sshActions.add(
                        MessageActionFactory.createAction(
                                config,
                                getConnection(),
                                ConnectionEndType.SERVER,
                                DhReplyandNewKeysMessage));
                sshActions.add(
                        MessageActionFactory.createAction(
                                config,
                                getConnection(),
                                ConnectionEndType.CLIENT,
                                new NewKeysMessage()));
                break;
            case DIFFIE_HELLMAN_GROUP_EXCHANGE:
                sshActions.add(
                        MessageActionFactory.createAction(
                                config,
                                getConnection(),
                                ConnectionEndType.CLIENT,
                                new DhGexKeyExchangeRequestMessage()));
                sshActions.add(
                        MessageActionFactory.createAction(
                                config,
                                getConnection(),
                                ConnectionEndType.SERVER,
                                new DhGexKeyExchangeGroupMessage()));
                sshActions.add(
                        MessageActionFactory.createAction(
                                config,
                                getConnection(),
                                ConnectionEndType.CLIENT,
                                new DhGexKeyExchangeInitMessage()));
                List<ProtocolMessage<?>> DhGexReplyandNewKeysMessage =
                        new ArrayList<ProtocolMessage<?>>();
                DhGexReplyandNewKeysMessage.add(new DhGexKeyExchangeReplyMessage());
                DhGexReplyandNewKeysMessage.add(new NewKeysMessage());
                sshActions.add(
                        MessageActionFactory.createAction(
                                config,
                                getConnection(),
                                ConnectionEndType.SERVER,
                                DhGexReplyandNewKeysMessage));
                sshActions.add(
                        MessageActionFactory.createAction(
                                config,
                                getConnection(),
                                ConnectionEndType.CLIENT,
                                new NewKeysMessage()));
                break;
            case ECDH:
                sshActions.add(
                        MessageActionFactory.createAction(
                                config,
                                getConnection(),
                                ConnectionEndType.CLIENT,
                                new EcdhKeyExchangeInitMessage()));
                List<ProtocolMessage<?>> EcdhReplyandNewKeysMessage =
                        new ArrayList<ProtocolMessage<?>>();
                EcdhReplyandNewKeysMessage.add(new EcdhKeyExchangeReplyMessage());
                EcdhReplyandNewKeysMessage.add(new NewKeysMessage());
                sshActions.add(
                        MessageActionFactory.createAction(
                                config,
                                getConnection(),
                                ConnectionEndType.SERVER,
                                EcdhReplyandNewKeysMessage));
                sshActions.add(
                        MessageActionFactory.createAction(
                                config,
                                getConnection(),
                                ConnectionEndType.CLIENT,
                                new NewKeysMessage()));
        }
        return sshActions;
    }

    public List<SshAction> createAuthPasswordActions() {
        List<SshAction> sshActions = new LinkedList<>();
        sshActions.add(new ActivateEncryptionAction());
        sshActions.add(
                MessageActionFactory.createAction(
                        config,
                        getConnection(),
                        ConnectionEndType.CLIENT,
                        new ServiceRequestMessage()));
        sshActions.add(
                MessageActionFactory.createAction(
                        config,
                        getConnection(),
                        ConnectionEndType.SERVER,
                        new ServiceAcceptMessage()));
        sshActions.add(
                MessageActionFactory.createAction(
                        config,
                        getConnection(),
                        ConnectionEndType.CLIENT,
                        new UserAuthPasswordMessage()));
        sshActions.add(
                MessageActionFactory.createAction(
                        config,
                        getConnection(),
                        ConnectionEndType.SERVER,
                        new UserAuthSuccessMessage()));
        return sshActions;
    }

    public List<SshAction> createConnectionProtocolActions() {
        List<SshAction> sshActions = new LinkedList<>();
        sshActions.add(
                MessageActionFactory.createAction(
                        config,
                        getConnection(),
                        ConnectionEndType.CLIENT,
                        new ChannelOpenMessage(1337, "session", 10000, 10000)));
        sshActions.add(
                MessageActionFactory.createAction(
                        config,
                        getConnection(),
                        ConnectionEndType.SERVER,
                        new ChannelOpenConfirmationMessage()));
        sshActions.add(
                MessageActionFactory.createAction(
                        config,
                        getConnection(),
                        ConnectionEndType.CLIENT,
                        new ChannelOpenMessage(1338, "session", 10000, 10000)));
        sshActions.add(
                MessageActionFactory.createAction(
                        config,
                        getConnection(),
                        ConnectionEndType.SERVER,
                        new ChannelOpenConfirmationMessage()));
        sshActions.add(
                MessageActionFactory.createAction(
                        config,
                        getConnection(),
                        ConnectionEndType.CLIENT,
                        new ChannelRequestExecMessage(1337, "nc -l -p 13370")));
        sshActions.add(
                MessageActionFactory.createAction(
                        config,
                        getConnection(),
                        ConnectionEndType.SERVER,
                        new ChannelWindowAdjustMessage()));
        sshActions.add(
                MessageActionFactory.createAction(
                        config,
                        getConnection(),
                        ConnectionEndType.CLIENT,
                        new ChannelWindowAdjustMessage(1337)));
        sshActions.add(
                MessageActionFactory.createAction(
                        config,
                        getConnection(),
                        ConnectionEndType.CLIENT,
                        new ChannelEofMessage(1337)));
        sshActions.add(
                MessageActionFactory.createAction(
                        config,
                        getConnection(),
                        ConnectionEndType.CLIENT,
                        new ChannelDataMessage(1337)));
        sshActions.add(
                MessageActionFactory.createAction(
                        config,
                        getConnection(),
                        ConnectionEndType.CLIENT,
                        new ChannelExtendedDataMessage(1337)));
        sshActions.add(
                MessageActionFactory.createAction(
                        config,
                        getConnection(),
                        ConnectionEndType.CLIENT,
                        new ChannelCloseMessage(1337)));
        sshActions.add(
                MessageActionFactory.createAction(
                        config,
                        getConnection(),
                        ConnectionEndType.SERVER,
                        new ChannelCloseMessage()));

        return sshActions;
    }
}
