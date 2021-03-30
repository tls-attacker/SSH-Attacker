/**
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2021 Ruhr University Bochum, Paderborn University,
 * and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.workflow.executor;

import de.rub.nds.sshattacker.core.config.ConfigIO;
import de.rub.nds.sshattacker.core.connection.AliasedConnection;
import de.rub.nds.sshattacker.core.exceptions.PreparationException;
import de.rub.nds.sshattacker.core.exceptions.WorkflowExecutionException;
import de.rub.nds.sshattacker.core.workflow.action.SshAction;
import de.rub.nds.sshattacker.core.state.SshContext;
import de.rub.nds.sshattacker.core.state.State;

import java.io.File;
import java.io.IOException;
import java.util.Arrays;
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

        List<SshContext> allSshContexts = state.getAllSshContexts();

        if (config.getWorkflowExecutorShouldOpen()) {
            for (SshContext ctx : allSshContexts) {
                AliasedConnection con = ctx.getConnection();
                try {
                    ctx.initTransportHandler();
                } catch (IOException e) {
                    LOGGER.error("Unable to initialize transportHandler: " + e + "\n"
                            + Arrays.toString(e.getStackTrace()));
                    LOGGER.error("Hostname: " + con.getHostname());
                    LOGGER.error("Port: " + con.getPort());

                }
                LOGGER.debug("Connection for " + ctx + " initiliazed");
            }
        }

        state.getWorkflowTrace().reset();
        int numSshContexts = allSshContexts.size();
        List<SshAction> sshActions = state.getWorkflowTrace().getSshActions();
        for (SshAction action : sshActions) {

            if ((state.getConfig().getStopActionsAfterDisconnect() && isReceivedDisconnectMessage())) {
                LOGGER.debug("Skipping all Actions, received Disconnect, StopActionsAfterDisconnect active");
                break;
            }
            if ((state.getConfig().getStopActionsAfterIOException() && isIoException())) {
                LOGGER.debug("Skipping all Actions, received IO Exception, StopActionsAfterIOException active");
                break;
            }

            try {
                action.execute(state);
            } catch (PreparationException | WorkflowExecutionException ex) {
                throw new WorkflowExecutionException("Problem while executing Action:" + action.toString(), ex);
            }
        }

        if (state.getConfig().getWorkflowExecutorShouldClose()) {
            for (SshContext ctx : state.getAllSshContexts()) {
                try {
                    ctx.getTransportHandler().closeConnection();
                } catch (IOException ex) {
                    LOGGER.warn("Could not close connection for context " + ctx);
                    LOGGER.debug(ex);
                }
            }
        }

        if (state.getConfig().getResetWorkflowtracesBeforeSaving()) {
            state.getWorkflowTrace().reset();
        }

        state.storeTrace();

        if (config.getConfigOutput() != null) {
            ConfigIO.write(config, new File(config.getConfigOutput()));
        }
    }

    private boolean isReceivedDisconnectMessage() {
        for (SshContext ctx : state.getAllSshContexts()) {
            if (ctx.getReceivedDisconnectMessage()) {
                return true;
            }
        }
        return false;
    }

    private boolean isIoException() {
        for (SshContext ctx : state.getAllSshContexts()) {
            if (ctx.isReceivedTransportHandlerException()) {
                return true;
            }
        }
        return false;
    }
}
