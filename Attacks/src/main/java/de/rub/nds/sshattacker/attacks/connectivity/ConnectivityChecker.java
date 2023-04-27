/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.attacks.connectivity;

import de.rub.nds.sshattacker.core.config.Config;
import de.rub.nds.sshattacker.core.connection.AliasedConnection;
import de.rub.nds.sshattacker.core.constants.RunningModeType;
import de.rub.nds.sshattacker.core.protocol.transport.message.VersionExchangeMessage;
import de.rub.nds.sshattacker.core.state.State;
import de.rub.nds.sshattacker.core.workflow.DefaultWorkflowExecutor;
import de.rub.nds.sshattacker.core.workflow.WorkflowExecutor;
import de.rub.nds.sshattacker.core.workflow.WorkflowTrace;
import de.rub.nds.sshattacker.core.workflow.action.ReceiveAction;
import de.rub.nds.sshattacker.core.workflow.action.SendAction;
import de.rub.nds.sshattacker.core.workflow.factory.WorkflowConfigurationFactory;
import de.rub.nds.sshattacker.core.workflow.factory.WorkflowTraceType;
import de.rub.nds.tlsattacker.transport.Connection;
import de.rub.nds.tlsattacker.transport.TransportHandler;
import de.rub.nds.tlsattacker.transport.TransportHandlerFactory;
import de.rub.nds.tlsattacker.transport.TransportHandlerType;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.io.IOException;

/** Utility class for checking if a server is online and supports SSH */
public class ConnectivityChecker {

    private static final Logger LOGGER = LogManager.getLogger();

    private final Connection connection;

    public ConnectivityChecker(Connection connection) {
        this.connection = connection;
        if (connection instanceof AliasedConnection) {
            ((AliasedConnection) connection).normalize((AliasedConnection) connection);
        }
    }

    /**
     * @return True if the server can be connected to
     */
    public boolean isConnectable() {
        if (connection.getTransportHandlerType() == null) {
            connection.setTransportHandlerType(TransportHandlerType.TCP);
        }
        if (connection.getTimeout() == null) {
            connection.setTimeout(5000);
        }
        TransportHandler handler = TransportHandlerFactory.createTransportHandler(connection);
        try {
            handler.initialize();
        } catch (IOException ex) {
            LOGGER.debug(ex);
            return false;
        }
        if (handler.isInitialized()) {
            try {
                handler.closeConnection();
            } catch (IOException ex) {
                LOGGER.debug(ex);
            }
            return true;
        } else {
            return false;
        }
    }

    /**
     * @return true, if the server speaks SSH
     */
    public boolean speaksSsh(Config config) {
        WorkflowConfigurationFactory factory = new WorkflowConfigurationFactory(config);
        WorkflowTrace trace =
                factory.createWorkflowTrace(
                        WorkflowTraceType.KEX_INIT_ONLY, RunningModeType.CLIENT);
        ReceiveAction receiveAction = new ReceiveAction(new VersionExchangeMessage());
        trace.setSshActions(new SendAction(new VersionExchangeMessage()), receiveAction);
        State state = new State(config, trace);
        WorkflowExecutor executor = new DefaultWorkflowExecutor(state);
        executor.executeWorkflow();
        if (receiveAction.getReceivedMessages().size() > 0) {
            return receiveAction.getReceivedMessages().get(0) instanceof VersionExchangeMessage;
        } else {
            return false;
        }
    }
}
