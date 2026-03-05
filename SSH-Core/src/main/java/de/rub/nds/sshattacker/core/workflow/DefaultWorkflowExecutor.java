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
import java.util.ArrayList;
import java.util.List;
import java.util.ListIterator;
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
        ListIterator<SshAction> iterator = sshActions.listIterator();
        while (iterator.hasNext()) {
            SshAction action = iterator.next();
            if (checkShouldStop()) {
                break;
            }

            if (config.isStopReceivingAfterDisconnect()
                    && hasReceivedDisconnectMessage()
                    && action instanceof ReceivingAction) {
                LOGGER.debug(
                        "Skipping all ReceiveActions, received DisconnectMessage, StopReceivingAfterDisconnect active");
                // Not sure if it really makes sense to keep sending data
                continue;
            }

            try {
                executeAction(action, state);
            } catch (SkipActionException ex) {
                continue;
            }

            // During the execution of the workflow trace, each executed action can generate new
            // dynamic actions that should be executed before the next action defined in the
            // workflow trace.
            if (config.getAllowDynamicGenerationOfActions()) {
                executeDynamicGeneratedActions(iterator);
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

    /**
     * All executed dynamically generated actions are added to the workflow trace at the position
     * before the next regular action.
     */
    private void executeDynamicGeneratedActions(ListIterator<SshAction> iterator) {
        for (SshContext sshContext : state.getAllSshContexts()) {
            ArrayList<SshAction> dynamicGeneratedActions = sshContext.getDynamicGeneratedActions();
            if (dynamicGeneratedActions != null) {
                for (SshAction dynamicAction : dynamicGeneratedActions) {
                    if (checkShouldStop()) {
                        break;
                    }

                    try {
                        executeAction(dynamicAction, state);
                        if (config.getAddDynamicallyGeneratedActionsToWorkflowTrace()) {
                            iterator.add(dynamicAction);
                        }
                    } catch (SkipActionException ex) {
                        LOGGER.debug("Dynamic generated action was not executed.");
                    }
                }
                dynamicGeneratedActions.clear();
            }
        }
    }

    private boolean checkShouldStop() {
        if (config.isStopActionsAfterDisconnect() && hasReceivedDisconnectMessage()) {
            LOGGER.debug(
                    "Skipping all Actions, received DisconnectMessage, StopActionsAfterDisconnect active");
            return true;
        }

        if (config.getStopActionsAfterIOException() && hasReceivedTransportHandlerException()) {
            LOGGER.debug(
                    "Skipping all Actions, received IO Exception, StopActionsAfterIOException active");
            return true;
        }
        return false;
    }
}
