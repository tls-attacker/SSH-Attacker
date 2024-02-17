/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.workflow.task;

import de.rub.nds.sshattacker.core.exceptions.TransportHandlerConnectException;
import de.rub.nds.sshattacker.core.state.State;
import de.rub.nds.sshattacker.core.workflow.WorkflowExecutor;
import de.rub.nds.sshattacker.core.workflow.WorkflowExecutorFactory;
import java.util.concurrent.Callable;
import java.util.function.Function;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public abstract class SshTask implements Task, Callable<Task> {

    private static final Logger LOGGER = LogManager.getLogger();

    private boolean hasError = false;

    private final int reexecutions;

    private final long additionalSleepTime;

    private final boolean increasingSleepTimes;

    private final long additionalTcpTimeout;

    private Function<State, Integer> beforeTransportPreInitCallback;

    private Function<State, Integer> beforeTransportInitCallback;

    private Function<State, Integer> afterTransportInitCallback;

    private Function<State, Integer> afterExecutionCallback;

    protected SshTask(int reexecutions) {
        super();
        this.reexecutions = reexecutions;
        additionalSleepTime = 1000;
        increasingSleepTimes = true;
        additionalTcpTimeout = 5000;
    }

    protected SshTask(
            int reexecutions,
            long additionalSleepTime,
            boolean increasingSleepTimes,
            long additionalTcpTimeout) {
        super();
        this.reexecutions = reexecutions;
        this.additionalSleepTime = additionalSleepTime;
        this.increasingSleepTimes = increasingSleepTimes;
        this.additionalTcpTimeout = additionalTcpTimeout;
    }

    @Override
    public Task call() {
        Throwable exception = null;
        long sleepTime = 0;
        for (int i = 0; i < reexecutions + 1; i++) {
            try {
                if (sleepTime > 0) {
                    Thread.sleep(sleepTime);
                }
                boolean executionSuccess = execute();
                if (executionSuccess) {
                    hasError = false;
                    break;
                } else {
                    LOGGER.debug(
                            "Could not execute task correctly. Increasing Timeout and reexecuting");
                    if (increasingSleepTimes) {
                        sleepTime += additionalSleepTime;
                    }
                    hasError = true;
                }
            } catch (TransportHandlerConnectException e) {
                LOGGER.warn("Could not connect to target. Sleep and Retry");
                try {
                    Thread.sleep(additionalTcpTimeout);
                } catch (InterruptedException ex) {
                    LOGGER.error("Interrupted during sleep", ex);
                }
                hasError = true;
                exception = e;
            } catch (Exception e) {
                hasError = true;
                if (increasingSleepTimes) {
                    sleepTime += additionalSleepTime;
                }
                exception = e;
            }
            if (i < reexecutions) {
                try {
                    reset();
                } catch (Throwable e) {
                    LOGGER.error("Could not reset state!", e);
                    hasError = true;
                    exception = e;
                    break;
                }
            }
        }
        if (hasError) {
            LOGGER.warn("Could not execute Workflow.", exception);
        }
        return this;
    }

    public boolean isHasError() {
        return hasError;
    }

    public abstract void reset();

    public int getReexecutions() {
        return reexecutions;
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

    public WorkflowExecutor getExecutor(State state) {
        WorkflowExecutor executor =
                WorkflowExecutorFactory.createWorkflowExecutor(
                        state.getConfig().getWorkflowExecutorType(), state);
        if (beforeTransportPreInitCallback != null
                && executor.getBeforeTransportPreInitCallback() == null) {
            executor.setBeforeTransportPreInitCallback(beforeTransportPreInitCallback);
        }
        if (beforeTransportInitCallback != null
                && executor.getBeforeTransportInitCallback() == null) {
            executor.setBeforeTransportInitCallback(beforeTransportInitCallback);
        }
        if (afterTransportInitCallback != null
                && executor.getAfterTransportInitCallback() == null) {
            executor.setAfterTransportInitCallback(afterTransportInitCallback);
        }
        if (afterExecutionCallback != null && executor.getAfterExecutionCallback() == null) {
            executor.setAfterExecutionCallback(afterExecutionCallback);
        }
        return executor;
    }
}
