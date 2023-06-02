/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.workflow;

import de.rub.nds.sshattacker.core.config.ConfigIO;
import de.rub.nds.sshattacker.core.exceptions.ActionExecutionException;
import de.rub.nds.sshattacker.core.exceptions.PreparationException;
import de.rub.nds.sshattacker.core.exceptions.SkipActionException;
import de.rub.nds.sshattacker.core.exceptions.WorkflowExecutionException;
import de.rub.nds.sshattacker.core.state.Context;
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
            try {
                initAllLayer();
            } catch (IOException ex) {
                throw new WorkflowExecutionException(
                        "Workflow not executed, could not initialize transport handler: ", ex);
            }
        }

        state.getWorkflowTrace().reset();
        state.setStartTimestamp(System.currentTimeMillis());
        List<SshAction> sshActions = state.getWorkflowTrace().getSshActions();
        for (SshAction action : sshActions) {

            if ((state.getConfig().getStopActionsAfterDisconnect()
                    && isDisconnectMessageReceived())) {
                LOGGER.debug(
                        "Received a DisconnectMessage, skipping all further actions because StopActionsAfterDisconnect is active");
                break;
            }
            if ((state.getConfig().getStopActionsAfterIOException() && isIoException())) {
                LOGGER.debug(
                        "Received an IOException, skipping all further actions because StopActionsAfterIOException is active");
                break;
            }

            try {
                this.executeAction(action, state);

                // TODO: Implement feature to check if message was received as expected.
                // We should accept unexpected messages to keep going in case something
                // unexpected happens.
                // action.isExecutedAsPlanned(...);
            } catch (PreparationException | WorkflowExecutionException ex) {
                throw new WorkflowExecutionException(
                        "Problem while executing action: " + action, ex);
            }
        }

        if (config.getWorkflowExecutorShouldClose()) {
            closeConnection();
        }

        if (state.getWorkflowTrace().executedAsPlanned()) {
            LOGGER.info("Workflow executed as planned.");
        } else {
            LOGGER.info("Workflow was not executed as planned.");
        }

        if (state.getConfig().getResetWorkflowtracesBeforeSaving()) {
            state.getWorkflowTrace().reset();
        }
        state.storeTrace();

        if (config.getConfigOutput() != null) {
            ConfigIO.write(config, new File(config.getConfigOutput()));
        }
    }

    protected void executeAction(SshAction action, State state) throws SkipActionException {
        try {
            action.execute(state);
        } catch (WorkflowExecutionException ex) {
            LOGGER.error("Fatal error during action execution, stopping execution: ", ex);
            state.setExecutionException(ex);
            throw ex;
        } catch (UnsupportedOperationException
                | PreparationException
                | ActionExecutionException ex) {
            state.setExecutionException(ex);
            LOGGER.warn("Not fatal error during action execution, skipping action: " + action, ex);
            throw new SkipActionException(ex);
        } catch (Exception ex) {
            LOGGER.error(
                    "Unexpected fatal error during action execution, stopping execution: ", ex);
            state.setExecutionException(ex);
            throw new WorkflowExecutionException(ex);
        } finally {
            state.setEndTimestamp(System.currentTimeMillis());
        }
    }

    private boolean isDisconnectMessageReceived() {
        for (Context context : state.getAllContexts()) {
            if (context.getSshContext().isDisconnectMessageReceived()) {
                return true;
            }
        }
        return false;
    }

    public boolean isIoException() {
        for (Context context : state.getAllContexts()) {
            if (context.getSshContext().hasReceivedTransportHandlerException()) {
                return true;
            }
        }
        return false;
    }
}
