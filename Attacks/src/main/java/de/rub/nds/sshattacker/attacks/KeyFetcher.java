/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.attacks;

import de.rub.nds.sshattacker.core.config.Config;
import de.rub.nds.sshattacker.core.constants.RunningModeType;
import de.rub.nds.sshattacker.core.protocol.common.ProtocolMessage;
import de.rub.nds.sshattacker.core.protocol.transport.message.RsaKeyExchangePubkeyMessage;
import de.rub.nds.sshattacker.core.state.State;
import de.rub.nds.sshattacker.core.workflow.DefaultWorkflowExecutor;
import de.rub.nds.sshattacker.core.workflow.WorkflowExecutor;
import de.rub.nds.sshattacker.core.workflow.WorkflowTrace;
import de.rub.nds.sshattacker.core.workflow.action.ReceiveAction;
import de.rub.nds.sshattacker.core.workflow.factory.WorkflowConfigurationFactory;
import de.rub.nds.sshattacker.core.workflow.factory.WorkflowTraceType;
import java.io.IOException;
import java.security.interfaces.RSAPublicKey;
import java.util.List;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/** Utility class to fetch the transient public key from an SSH RSA key exchange */
public class KeyFetcher {

    private static final Logger LOGGER = LogManager.getLogger();

    public static RSAPublicKey fetchRsaTransientKey(Config config) {
        WorkflowConfigurationFactory factory = new WorkflowConfigurationFactory(config);
        WorkflowTrace trace =
                factory.createWorkflowTrace(
                        WorkflowTraceType.START_KEYEXCHANGE, RunningModeType.CLIENT);

        ReceiveAction receiveAction = new ReceiveAction(new RsaKeyExchangePubkeyMessage());
        trace.addSshAction(receiveAction);

        State state = new State(config, trace);

        WorkflowExecutor workflowExecutor = new DefaultWorkflowExecutor(state);
        try {
            workflowExecutor.executeWorkflow();

            if (!state.getSshContext().getTransportHandler().isClosed()) {
                state.getSshContext().getTransportHandler().closeConnection();
            }

        } catch (IOException e) {
            LOGGER.warn("Could not fetch server's RSA host key.");
            LOGGER.debug(e);
        }

        List<ProtocolMessage<?>> receivedMessages = receiveAction.getReceivedMessages();

        if (receivedMessages.size() > 0
                && receivedMessages.get(0) instanceof RsaKeyExchangePubkeyMessage) {
            return ((RsaKeyExchangePubkeyMessage) receivedMessages.get(0)).getPublicKey();
        } else {
            LOGGER.warn("Could not fetch server's RSA host key, did not receive PubkeyMessage.");
            return null;
        }
    }
}
