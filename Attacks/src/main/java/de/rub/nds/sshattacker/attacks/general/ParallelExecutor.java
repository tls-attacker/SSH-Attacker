/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.attacks.general;

import de.rub.nds.sshattacker.attacks.task.SshTask;
import de.rub.nds.sshattacker.attacks.task.StateExecutionTask;
import de.rub.nds.sshattacker.attacks.task.Task;
import de.rub.nds.sshattacker.core.state.State;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedList;
import java.util.List;
import java.util.concurrent.*;
import java.util.function.Function;

/** Executes tasks in parallel */
public class ParallelExecutor {

    private static final Logger LOGGER = LogManager.getLogger();

    private final ThreadPoolExecutor executorService;
    private Callable<Integer> timeoutAction;

    private final int size;
    private boolean shouldShutdown = false;

    private final int reexecutions;

    private Function<State, Integer> defaultBeforeTransportPreInitCallback = null;

    private Function<State, Integer> defaultBeforeTransportInitCallback = null;

    private Function<State, Integer> defaultAfterTransportInitCallback = null;

    private Function<State, Integer> defaultAfterExecutionCallback = null;

    public ParallelExecutor(int size, int reexecutions, ThreadPoolExecutor executorService) {
        this.executorService = executorService;
        this.reexecutions = reexecutions;
        this.size = size;
        if (reexecutions < 0) {
            throw new IllegalArgumentException("Reexecutions is below zero");
        }
    }

    public ParallelExecutor(ThreadPoolExecutor executorService, int reexecutions) {
        this(-1, reexecutions, executorService);
    }

    public ParallelExecutor(int size, int reexecutions) {
        this(
                size,
                reexecutions,
                new ThreadPoolExecutor(size, size, 10, TimeUnit.DAYS, new LinkedBlockingDeque<>()));
    }

    public ParallelExecutor(int size, int reexecutions, ThreadFactory factory) {
        this(
                size,
                reexecutions,
                new ThreadPoolExecutor(
                        size, size, 5, TimeUnit.MINUTES, new LinkedBlockingDeque<>(), factory));
    }

    protected Future<Task> addTask(SshTask task) {
        if (executorService.isShutdown()) {
            throw new RuntimeException("Cannot add Tasks to already shutdown executor");
        }
        if (defaultBeforeTransportPreInitCallback != null
                && task.getBeforeTransportPreInitCallback() == null) {
            task.setBeforeTransportPreInitCallback(defaultBeforeTransportPreInitCallback);
        }
        if (defaultBeforeTransportInitCallback != null
                && task.getBeforeTransportInitCallback() == null) {
            task.setBeforeTransportInitCallback(defaultBeforeTransportInitCallback);
        }
        if (defaultAfterTransportInitCallback != null
                && task.getAfterTransportInitCallback() == null) {
            task.setAfterTransportInitCallback(defaultAfterTransportInitCallback);
        }
        if (defaultAfterExecutionCallback != null && task.getAfterExecutionCallback() == null) {
            task.setAfterExecutionCallback(defaultAfterExecutionCallback);
        }
        return executorService.submit(task);
    }

    protected Future<Task> addStateTask(State state) {
        return addTask(new StateExecutionTask(state, reexecutions));
    }

    public void bulkExecuteStateTasks(Iterable<State> stateList) {
        List<Future<?>> futureList = new LinkedList<>();
        for (State state : stateList) {
            futureList.add(addStateTask(state));
        }
        for (Future<?> future : futureList) {
            try {
                future.get();
            } catch (InterruptedException | ExecutionException ex) {
                throw new RuntimeException("Failed to execute tasks!", ex);
            }
        }
    }

    public void bulkExecuteStateTasks(State... states) {
        this.bulkExecuteStateTasks(new ArrayList<>(Arrays.asList(states)));
    }

    public List<Task> bulkExecuteTasks(Iterable<SshTask> taskList) {
        List<Future<Task>> futureList = new LinkedList<>();
        List<Task> resultList = new ArrayList<>(0);
        for (SshTask tlStask : taskList) {
            futureList.add(addTask(tlStask));
        }
        for (Future<Task> future : futureList) {
            try {
                resultList.add(future.get());
            } catch (InterruptedException | ExecutionException ex) {
                throw new RuntimeException("Failed to execute tasks!", ex);
            }
        }
        return resultList;
    }

    @SuppressWarnings("UnusedReturnValue")
    public List<Task> bulkExecuteTasks(SshTask... tasks) {
        return this.bulkExecuteTasks(new ArrayList<>(Arrays.asList(tasks)));
    }

    public int getSize() {
        return size;
    }

    public void shutdown() {
        shouldShutdown = true;
        executorService.shutdown();
    }

    /**
     * Creates a new thread monitoring the executorService. If the time since the last {@link
     * SshTask} was finished exceeds the timeout, the function assiged to {@link
     * ParallelExecutor#timeoutAction } is executed. The {@link ParallelExecutor#timeoutAction }
     * function can, for example, try to restart the client/server, so that the remaining {@link
     * SshTask}s can be finished.
     *
     * @param timeout The timeout in milliseconds
     */
    public void armTimeoutAction(int timeout) {
        if (timeoutAction == null) {
            LOGGER.warn("No TimeoutAction set, this won't do anything");
            return;
        }

        new Thread(() -> monitorExecution(timeout)).start();
    }

    private void monitorExecution(int timeout) {
        long timeoutTime = System.currentTimeMillis() + timeout;
        long lastCompletedCount = 0;
        while (!shouldShutdown) {
            long completedCount = executorService.getCompletedTaskCount();
            if (executorService.getActiveCount() == 0 || completedCount != lastCompletedCount) {
                timeoutTime = System.currentTimeMillis() + timeout;
                lastCompletedCount = completedCount;
            } else if (System.currentTimeMillis() > timeoutTime) {
                LOGGER.debug("Timeout");
                try {
                    int exitCode = timeoutAction.call();
                    if (exitCode != 0) {
                        throw new RuntimeException(
                                "TimeoutAction did terminate with code " + exitCode);
                    }
                    timeoutTime = System.currentTimeMillis() + timeout;
                } catch (Exception e) {
                    LOGGER.warn("TimeoutAction did not succeed", e);
                }
            }
        }
    }

    public int getReexecutions() {
        return reexecutions;
    }

    public Callable<Integer> getTimeoutAction() {
        return timeoutAction;
    }

    public void setTimeoutAction(Callable<Integer> timeoutAction) {
        this.timeoutAction = timeoutAction;
    }

    public Function<State, Integer> getDefaultBeforeTransportPreInitCallback() {
        return defaultBeforeTransportPreInitCallback;
    }

    public void setDefaultBeforeTransportPreInitCallback(
            Function<State, Integer> defaultBeforeTransportPreInitCallback) {
        this.defaultBeforeTransportPreInitCallback = defaultBeforeTransportPreInitCallback;
    }

    public Function<State, Integer> getDefaultBeforeTransportInitCallback() {
        return defaultBeforeTransportInitCallback;
    }

    public void setDefaultBeforeTransportInitCallback(
            Function<State, Integer> defaultBeforeTransportInitCallback) {
        this.defaultBeforeTransportInitCallback = defaultBeforeTransportInitCallback;
    }

    public Function<State, Integer> getDefaultAfterTransportInitCallback() {
        return defaultAfterTransportInitCallback;
    }

    public void setDefaultAfterTransportInitCallback(
            Function<State, Integer> defaultAfterTransportInitCallback) {
        this.defaultAfterTransportInitCallback = defaultAfterTransportInitCallback;
    }

    public Function<State, Integer> getDefaultAfterExecutionCallback() {
        return defaultAfterExecutionCallback;
    }

    public void setDefaultAfterExecutionCallback(
            Function<State, Integer> defaultAfterExecutionCallback) {
        this.defaultAfterExecutionCallback = defaultAfterExecutionCallback;
    }
}
