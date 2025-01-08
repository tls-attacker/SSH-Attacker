/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.workflow;

import de.rub.nds.sshattacker.core.exceptions.SkipActionException;
import de.rub.nds.sshattacker.core.exceptions.WorkflowExecutionException;
import de.rub.nds.sshattacker.core.state.SshContext;
import de.rub.nds.sshattacker.core.state.State;
import de.rub.nds.sshattacker.core.workflow.action.ReceivingAction;
import de.rub.nds.sshattacker.core.workflow.action.SshAction;
import de.rub.nds.sshattacker.core.workflow.action.executor.WorkflowExecutorType;
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
            for (SshContext context : state.getAllSshContexts()) {
                initTransportHandler(context);
            }
        }

        if (config.getResetWorkflowTraceBeforeExecution()) {
            state.getWorkflowTrace().reset(config.getResetModifiableVariables());
        }

        state.setStartTimestamp(System.currentTimeMillis());
        List<SshAction> sshActions = state.getWorkflowTrace().getSshActions();
        for (SshAction action : sshActions) {
            if (config.isStopActionsAfterDisconnect() && hasReceivedDisconnectMessage()) {
                LOGGER.debug(
                        "Skipping all Actions, received DisconnectMessage, StopActionsAfterDisconnect active");
                break;
            }
            if (config.isStopReceivingAfterDisconnect()
                    && hasReceivedDisconnectMessage()
                    && action instanceof ReceivingAction) {
                LOGGER.debug(
                        "Skipping all ReceiveActions, received FatalAlert, StopActionsAfterFatal active");
                break;
            }
            if (config.getStopActionsAfterIOException() && hasReceivedTransportHandlerException()) {
                LOGGER.debug(
                        "Skipping all Actions, received IO Exception, StopActionsAfterIOException active");
                break;
            }

            try {
                executeAction(action, state);
            } catch (SkipActionException ex) {
                continue;
            }

            if (config.getStopTraceAfterUnexpected() && !action.executedAsPlanned()) {
                LOGGER.debug("Skipping all Actions, action did not execute as planned.");
                break;
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

        if (config.getResetWorkflowTraceBeforeSaving()) {
            state.getWorkflowTrace().reset(config.getResetModifiableVariables());
        }

        try {
            if (getAfterExecutionCallback() != null) {
                getAfterExecutionCallback().apply(state);
            }
        } catch (Exception ex) {
            LOGGER.trace("Error during AfterExecutionCallback", ex);
        }
    }
}
