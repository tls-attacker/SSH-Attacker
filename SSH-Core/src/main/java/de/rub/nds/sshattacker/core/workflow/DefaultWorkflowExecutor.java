/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.workflow;

import de.rub.nds.sshattacker.core.config.ConfigIO;
import de.rub.nds.sshattacker.core.exceptions.PreparationException;
import de.rub.nds.sshattacker.core.exceptions.WorkflowExecutionException;
import de.rub.nds.sshattacker.core.state.SshContext;
import de.rub.nds.sshattacker.core.state.State;
import de.rub.nds.sshattacker.core.workflow.action.SshAction;
import de.rub.nds.sshattacker.core.workflow.action.executor.WorkflowExecutorType;
import java.io.File;
import java.io.IOException;
import java.util.List;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class DefaultWorkflowExecutor extends WorkflowExecutor {

    private static final Logger LOGGER = LogManager.getLogger();

    public DefaultWorkflowExecutor(State state) {
        super(WorkflowExecutorType.DEFAULT, state);
    }

    @Override
    public void executeWorkflow() throws WorkflowExecutionException {
        if (config.getWorkflowExecutorShouldOpen()) {
            state.getAllSshContexts()
                    .forEach(
                            ctx -> {
                                ctx.initTransportHandler();
                                LOGGER.debug("Connection for {} initialized", ctx);
                            });
        }

        state.getWorkflowTrace().reset();
        List<SshAction> sshActions = state.getWorkflowTrace().getSshActions();
        for (SshAction action : sshActions) {

            if (state.getConfig().getStopActionsAfterDisconnect()
                    && isDisconnectMessageReceived()) {
                LOGGER.debug(
                        "Received a DisconnectMessage, skipping all further actions because StopActionsAfterDisconnect is active");
                break;
            }
            if (state.getConfig().getStopActionsAfterIOException() && isIoException()) {
                LOGGER.debug(
                        "Received an IOException, skipping all further actions because StopActionsAfterIOException is active");
                break;
            }

            try {
                action.execute(state);
                // TODO: Implement feature to check if message was received as expected.
                // We should accept unexpected messages to keep going in case something
                // unexpected happens.
                // action.isExecutedAsPlanned(...);
            } catch (PreparationException | WorkflowExecutionException ex) {
                throw new WorkflowExecutionException(
                        "Problem while executing action: " + action, ex);
            }
        }

        if (state.getConfig().getWorkflowExecutorShouldClose()) {
            state.getAllSshContexts()
                    .forEach(
                            ctx -> {
                                try {
                                    ctx.getTransportHandler().closeConnection();
                                } catch (IOException ex) {
                                    LOGGER.warn("Could not close connection for context {}", ctx);
                                    LOGGER.debug(ex);
                                }
                            });
        }

        if (state.getConfig().getResetWorkflowtracesBeforeSaving()) {
            state.getWorkflowTrace().reset();
        }
        state.storeTrace();

        if (config.getConfigOutput() != null) {
            ConfigIO.write(config, new File(config.getConfigOutput()));
        }
    }

    private boolean isDisconnectMessageReceived() {
        return state.getAllSshContexts().stream().anyMatch(SshContext::isDisconnectMessageReceived);
    }

    private boolean isIoException() {
        return state.getAllSshContexts().stream()
                .anyMatch(SshContext::hasReceivedTransportHandlerException);
    }
}
