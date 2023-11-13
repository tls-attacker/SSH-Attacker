/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.attacks.general;

import de.rub.nds.modifiablevariable.VariableModification;
import de.rub.nds.modifiablevariable.string.StringModificationFactory;
import de.rub.nds.sshattacker.core.config.Config;
import de.rub.nds.sshattacker.core.constants.MessageIdConstantSSH1;
import de.rub.nds.sshattacker.core.constants.ProtocolVersion;
import de.rub.nds.sshattacker.core.constants.RunningModeType;
import de.rub.nds.sshattacker.core.crypto.keys.CustomRsaPublicKey;
import de.rub.nds.sshattacker.core.protocol.common.ProtocolMessage;
import de.rub.nds.sshattacker.core.protocol.ssh1.message.DisconnectMessageSSH1;
import de.rub.nds.sshattacker.core.protocol.ssh1.message.ServerPublicKeyMessage;
import de.rub.nds.sshattacker.core.protocol.transport.message.RsaKeyExchangePubkeyMessage;
import de.rub.nds.sshattacker.core.state.State;
import de.rub.nds.sshattacker.core.workflow.DefaultWorkflowExecutor;
import de.rub.nds.sshattacker.core.workflow.WorkflowExecutor;
import de.rub.nds.sshattacker.core.workflow.WorkflowTrace;
import de.rub.nds.sshattacker.core.workflow.action.ReceiveAction;
import de.rub.nds.sshattacker.core.workflow.action.SendAction;
import de.rub.nds.sshattacker.core.workflow.factory.WorkflowConfigurationFactory;
import de.rub.nds.sshattacker.core.workflow.factory.WorkflowTraceType;
import java.io.IOException;
import java.security.interfaces.RSAPublicKey;
import java.util.ArrayList;
import java.util.List;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/** Utility class to fetch public keys from SSH servers */
public class KeyFetcher {

    private static final Logger LOGGER = LogManager.getLogger();

    /** Fetches the transient public key from an RSA key-exchange */
    public static RSAPublicKey fetchRsaTransientKey(Config config) {
        if (config.getProtocolVersion() == ProtocolVersion.SSH2) {
            return fetchRsaTransientKey(config, 0, 5, ProtocolVersion.SSH2);
        } else if (config.getProtocolVersion() == ProtocolVersion.SSH1) {
            return fetchRsaTransientKey(config, 0, 5, ProtocolVersion.SSH1);
        } else {
            return null;
        }
    }

    public static RSAPublicKey fetchRsaTransientKey(Config config, int maxAttempts) {
        return fetchRsaTransientKey(config, 0, maxAttempts, ProtocolVersion.SSH2);
    }

    private static RSAPublicKey fetchRsaTransientKey(
            Config config, int attempt, int maxAttempts, ProtocolVersion version) {
        WorkflowConfigurationFactory factory = new WorkflowConfigurationFactory(config);

        if (version == ProtocolVersion.SSH2) {
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
                            String.format(
                                    "Encountered IOException on socket in attempt %d, retrying...",
                                    attempt));
                    return fetchRsaTransientKey(config, attempt + 1, maxAttempts, version);
                } else {
                    LOGGER.warn("Could not fetch server's RSA host key, encountered IOException");
                    LOGGER.debug(e);
                    return null;
                }
            }

            List<ProtocolMessage<?>> receivedMessages = receiveAction.getReceivedMessages();

            if (receivedMessages.size() > 0
                    && receivedMessages.get(0) instanceof RsaKeyExchangePubkeyMessage) {
                return ((RsaKeyExchangePubkeyMessage) receivedMessages.get(0))
                        .getTransientPublicKey()
                        .getPublicKey();
            } else {
                if (attempt < maxAttempts) {
                    LOGGER.debug(
                            String.format(
                                    "Did not receive PubkeyMessage in attempt %d, retrying...",
                                    attempt));
                    return fetchRsaTransientKey(config, attempt + 1, maxAttempts, version);
                } else {
                    LOGGER.warn(
                            "Could not fetch server's RSA host key, did not receive PubkeyMessage.");
                    return null;
                }
            }
        } else {
            WorkflowTrace trace =
                    factory.createWorkflowTrace(
                            WorkflowTraceType.KEX_SSH1_ONLY, RunningModeType.CLIENT);

            ReceiveAction receiveAction = new ReceiveAction(new ServerPublicKeyMessage());
            trace.addSshAction(receiveAction);

            State state = new State(config, trace);
            WorkflowExecutor workflowExecutor = new DefaultWorkflowExecutor(state);

            workflowExecutor.executeWorkflow();

            /*            try {
                workflowExecutor.executeWorkflow();

                if (!state.getSshContext().getTransportHandler().isClosed()) {
                    LOGGER.debug("Running into");
                    state.getSshContext().getTransportHandler().closeConnection();
                }
            } catch (IOException e) {
                if (attempt < maxAttempts) {
                    LOGGER.debug(
                            String.format(
                                    "Encountered IOException on socket in attempt %d, retrying...",
                                    attempt));
                    return fetchRsaTransientKey(config, attempt + 1, maxAttempts, version);
                } else {
                    LOGGER.warn("Could not fetch server's RSA host key, encountered IOException");
                    LOGGER.debug(e);
                    return null;
                }
            }*/

            List<ProtocolMessage<?>> receivedMessages = receiveAction.getReceivedMessages();

            if (receivedMessages.size() > 0
                    && receivedMessages.get(0) instanceof ServerPublicKeyMessage) {
                return ((ServerPublicKeyMessage) receivedMessages.get(0))
                        .getServerKey()
                        .getPublicKey();
            } else {
                if (attempt < maxAttempts) {
                    LOGGER.debug(
                            String.format(
                                    "Did not receive PubkeyMessage in attempt %d, retrying...",
                                    attempt));
                    return fetchRsaTransientKey(config, attempt + 1, maxAttempts, version);
                } else {
                    LOGGER.warn(
                            "Could not fetch server's RSA host key, did not receive PubkeyMessage.");
                    return null;
                }
            }
        }
    }

    public static List<CustomRsaPublicKey> fetchRsaSsh1Keys(Config config) {
        return fetchRsaSsh1Keys(config, 0, 5);
    }

    public static List<CustomRsaPublicKey> fetchRsaSsh1Keys(
            Config config, int attempt, int maxAttempts) {
        WorkflowConfigurationFactory factory = new WorkflowConfigurationFactory(config);

        WorkflowTrace trace =
                factory.createWorkflowTrace(
                        WorkflowTraceType.KEX_SSH1_ONLY, RunningModeType.CLIENT);

        ReceiveAction receiveAction = new ReceiveAction(new ServerPublicKeyMessage());
        trace.addSshAction(receiveAction);

        DisconnectMessageSSH1 disconnectMessage = new DisconnectMessageSSH1();
        disconnectMessage.setDisconnectReason("fetching Keys");
        VariableModification<String> newValue =
                StringModificationFactory.explicitValue("fetching Keys");
        disconnectMessage.getDisconnectReason().setModification(newValue);

        LOGGER.debug(disconnectMessage.getDisconnectReason());
        LOGGER.debug(disconnectMessage.toShortString());

        disconnectMessage.setMessageId(MessageIdConstantSSH1.SSH_MSG_DISCONNECT.getId());
        SendAction disconnectAction = new SendAction(disconnectMessage);
        trace.addSshAction(disconnectAction);

        State state = new State(config, trace);
        WorkflowExecutor workflowExecutor = new DefaultWorkflowExecutor(state);

        workflowExecutor.executeWorkflow();

        List<ProtocolMessage<?>> receivedMessages = receiveAction.getReceivedMessages();
        LOGGER.info(receivedMessages.size());
        LOGGER.info(receivedMessages.get(0).toString());

        if (receivedMessages.size() > 0
                && receivedMessages.get(0) instanceof ServerPublicKeyMessage) {

            List<CustomRsaPublicKey> rsaPublicKeys = new ArrayList<>();

            rsaPublicKeys.add(
                    ((ServerPublicKeyMessage) receivedMessages.get(0))
                            .getServerKey()
                            .getPublicKey());
            rsaPublicKeys.add(
                    ((ServerPublicKeyMessage) receivedMessages.get(0)).getHostKey().getPublicKey());

            return rsaPublicKeys;
        } else {
            if (attempt < maxAttempts) {
                LOGGER.debug(
                        String.format(
                                "Did not receive PubkeyMessage in attempt %d, retrying...",
                                attempt));
                try {
                    Thread.sleep(5000);
                } catch (InterruptedException e) {
                    throw new RuntimeException(e);
                }
                return fetchRsaSsh1Keys(config, attempt + 1, maxAttempts);
            } else {
                LOGGER.warn(
                        "Could not fetch server's RSA host key, did not receive PubkeyMessage.");
                return null;
            }
        }
    }
}
