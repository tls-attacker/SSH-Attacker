/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.workflow;

import de.rub.nds.sshattacker.core.config.Config;
import de.rub.nds.sshattacker.core.exceptions.*;
import de.rub.nds.sshattacker.core.state.SshContext;
import de.rub.nds.sshattacker.core.state.State;
import de.rub.nds.sshattacker.core.workflow.action.SshAction;
import de.rub.nds.sshattacker.core.workflow.action.executor.WorkflowExecutorType;
import de.rub.nds.tlsattacker.transport.TransportHandlerFactory;
import de.rub.nds.tlsattacker.transport.tcp.ClientTcpTransportHandler;
import java.io.IOException;
import java.util.function.Function;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public abstract class WorkflowExecutor {

    private static final Logger LOGGER = LogManager.getLogger();

    private Function<State, Integer> beforeTransportPreInitCallback;
    private Function<State, Integer> beforeTransportInitCallback;
    private Function<State, Integer> afterTransportInitCallback;
    private Function<State, Integer> afterExecutionCallback;

    protected final WorkflowExecutorType type;

    protected final State state;
    protected final Config config;

    /**
     * Prepare a workflow trace for execution according to the given state and executor type. Try
     * various ways to initialize a workflow trace and add it to the state. For workflow creation,
     * use the first method which does not return null, in the following order:
     * state.getWorkflowTrace(), state.config.getWorkflowInput(), config.getWorkflowTraceType().
     *
     * @param type of the workflow executor (currently only DEFAULT)
     * @param state to work on
     */
    protected WorkflowExecutor(WorkflowExecutorType type, State state) {
        super();
        this.type = type;
        this.state = state;
        config = state.getConfig();
    }

    public abstract void executeWorkflow() throws WorkflowExecutionException;

    public void initTransportHandler(SshContext context) {
        if (context.getTransportHandler() == null) {
            if (context.getConnection() == null) {
                throw new ConfigurationException("Connection end not set");
            }
            context.setTransportHandler(
                    TransportHandlerFactory.createTransportHandler(context.getConnection()));
            context.getTransportHandler()
                    .setResetClientSourcePort(config.getResetClientSourcePort());
            if (context.getTransportHandler() instanceof ClientTcpTransportHandler) {
                ((ClientTcpTransportHandler) context.getTransportHandler())
                        .setRetryFailedSocketInitialization(
                                config.getRetryFailedClientTcpSocketInitialization());
            }
        }

        try {
            if (beforeTransportPreInitCallback != null) {
                beforeTransportPreInitCallback.apply(state);
            }
            context.getTransportHandler().preInitialize();
            if (beforeTransportInitCallback != null) {
                beforeTransportInitCallback.apply(state);
            }
            context.getTransportHandler().initialize();
            if (afterTransportInitCallback != null) {
                afterTransportInitCallback.apply(state);
            }
        } catch (NullPointerException | NumberFormatException ex) {
            throw new ConfigurationException(
                    "Invalid values in " + context.getConnection().toString(), ex);
        } catch (Exception ex) {
            throw new TransportHandlerConnectException(
                    "Unable to initialize the transport handler with: "
                            + context.getConnection().toString(),
                    ex);
        }
    }

    protected static void executeAction(SshAction action, State state) throws SkipActionException {
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
            LOGGER.error(
                    "Not fatal error during action execution, skipping action: {}", action, ex);
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

    public Function<State, Integer> getBeforeTransportPreInitCallback() {
        return beforeTransportPreInitCallback;
    }

    public void setBeforeTransportPreInitCallback(
            Function<State, Integer> beforeTransportPreInitCallback) {
        this.beforeTransportPreInitCallback = beforeTransportPreInitCallback;
    }

    public Function<State, Integer> getBeforeTransportInitCallback() {
        return beforeTransportInitCallback;
    }

    public void setBeforeTransportInitCallback(
            Function<State, Integer> beforeTransportInitCallback) {
        this.beforeTransportInitCallback = beforeTransportInitCallback;
    }

    public Function<State, Integer> getAfterTransportInitCallback() {
        return afterTransportInitCallback;
    }

    public void setAfterTransportInitCallback(Function<State, Integer> afterTransportInitCallback) {
        this.afterTransportInitCallback = afterTransportInitCallback;
    }

    public Function<State, Integer> getAfterExecutionCallback() {
        return afterExecutionCallback;
    }

    public void setAfterExecutionCallback(Function<State, Integer> afterExecutionCallback) {
        this.afterExecutionCallback = afterExecutionCallback;
    }

    public void closeConnection() {
        for (SshContext context : state.getAllSshContexts()) {
            try {
                context.getTransportHandler().closeConnection();
            } catch (IOException ex) {
                LOGGER.warn("Could not close connection for context {}", context);
                LOGGER.debug(ex);
            }
        }
    }

    public boolean hasReceivedDisconnectMessage() {
        for (SshContext context : state.getAllSshContexts()) {
            if (context.isDisconnectMessageReceived()) {
                return true;
            }
        }
        return false;
    }

    public boolean hasReceivedTransportHandlerException() {
        for (SshContext context : state.getAllSshContexts()) {
            if (context.hasReceivedTransportHandlerException()) {
                return true;
            }
        }
        return false;
    }
}
