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
import de.rub.nds.sshattacker.core.layer.LayerStackFactory;
import de.rub.nds.sshattacker.core.state.Context;
import de.rub.nds.sshattacker.core.state.State;
import de.rub.nds.sshattacker.core.workflow.action.SshAction;
import de.rub.nds.sshattacker.core.workflow.action.executor.WorkflowExecutorType;
import de.rub.nds.tlsattacker.transport.TransportHandlerFactory;
import java.io.IOException;
import java.util.function.Function;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public abstract class WorkflowExecutor {

    private static final Logger LOGGER = LogManager.getLogger();

    protected final WorkflowExecutorType type;

    protected final State state;
    protected final Config config;

    private Function<State, Integer> beforeTransportPreInitCallback = null;

    private Function<State, Integer> beforeTransportInitCallback = null;

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

    private Function<State, Integer> afterTransportInitCallback = null;

    private Function<State, Integer> afterExecutionCallback = null;

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

    public void initProtocolStack(Context context) throws IOException {
        LOGGER.debug("[bro] Layerstack-3");
        context.setLayerStack(
                LayerStackFactory.createLayerStack(config.getDefaultLayerConfiguration(), context));
    }

    public void initAllLayer() throws IOException {
        for (Context ctx : state.getAllContexts()) {
            initTransportHandler(ctx);
            initProtocolStack(ctx);
        }
    }

    public void initTransportHandler(Context context) {

        if (context.getTransportHandler() == null) {
            if (context.getConnection() == null) {
                throw new ConfigurationException("Connection end not set");
            }
            context.setTransportHandler(
                    TransportHandlerFactory.createTransportHandler(context.getConnection()));
            context.getTransportHandler()
                    .setResetClientSourcePort(config.isResetClientSourcePort());
        }

        try {
            if (getBeforeTransportPreInitCallback() != null) {
                getBeforeTransportPreInitCallback().apply(state);
            }
            context.getTransportHandler().preInitialize();
            if (getBeforeTransportInitCallback() != null) {
                getBeforeTransportInitCallback().apply(state);
            }
            context.getTransportHandler().initialize();
            if (getAfterTransportInitCallback() != null) {
                getAfterTransportInitCallback().apply(state);
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
            LOGGER.warn("Not fatal error during action execution, skipping action: {}", action, ex);
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

    public void closeConnection() {
        for (Context context : state.getAllContexts()) {
            try {
                context.getTransportHandler().closeConnection();
            } catch (IOException ex) {
                LOGGER.warn("Could not close connection for context " + context);
                LOGGER.debug(ex);
            }
        }
    }
}
