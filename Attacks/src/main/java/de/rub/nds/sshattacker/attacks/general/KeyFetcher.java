/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.attacks.general;

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

/** Utility class to fetch public keys from SSH servers */
public final class KeyFetcher {

    private static final Logger LOGGER = LogManager.getLogger();

    private KeyFetcher() {
        super();
    }

    /**
     * Fetches the transient public key from an RSA key-exchange.
     *
     * @param config Config object which is used to instantiate the underlying SSH attacker.
     * @return The transient public key used during key exchange.
     */
    public static RSAPublicKey fetchRsaTransientKey(Config config) {
        return fetchRsaTransientKey(config, 0, 5);
    }

    public static RSAPublicKey fetchRsaTransientKey(Config config, int maxAttempts) {
        return fetchRsaTransientKey(config, 0, maxAttempts);
    }

    private static RSAPublicKey fetchRsaTransientKey(Config config, int attempt, int maxAttempts) {
        WorkflowConfigurationFactory factory = new WorkflowConfigurationFactory(config);
        WorkflowTrace trace =
                factory.createWorkflowTrace(
                        WorkflowTraceType.KEX_INIT_ONLY, RunningModeType.CLIENT);

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
            if (attempt < maxAttempts) {
                LOGGER.debug(
                        "Encountered IOException on socket in attempt {}, retrying...", attempt);
                return fetchRsaTransientKey(config, attempt + 1, maxAttempts);
            } else {
                LOGGER.warn("Could not fetch server's RSA host key, encountered IOException");
                LOGGER.debug(e);
                return null;
            }
        }

        List<ProtocolMessage<?>> receivedMessages = receiveAction.getReceivedMessages();

        if (!receivedMessages.isEmpty()
                && receivedMessages.get(0) instanceof RsaKeyExchangePubkeyMessage) {
            return ((RsaKeyExchangePubkeyMessage) receivedMessages.get(0))
                    .getTransientPublicKey()
                    .getPublicKey();
        } else {
            if (attempt < maxAttempts) {
                LOGGER.debug("Did not receive PubkeyMessage in attempt {}, retrying...", attempt);
                return fetchRsaTransientKey(config, attempt + 1, maxAttempts);
            } else {
                LOGGER.warn(
                        "Could not fetch server's RSA host key, did not receive PubkeyMessage.");
                return null;
            }
        }
    }
}
