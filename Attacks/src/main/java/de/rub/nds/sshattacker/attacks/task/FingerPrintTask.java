/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.attacks.task;

import de.rub.nds.sshattacker.attacks.response.ResponseExtractor;
import de.rub.nds.sshattacker.attacks.response.ResponseFingerprint;
import de.rub.nds.sshattacker.core.state.State;
import de.rub.nds.sshattacker.core.workflow.WorkflowExecutor;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.io.IOException;

/** Executes a workflow and stores the server's response */
public class FingerPrintTask extends SshTask {

    private static final Logger LOGGER = LogManager.getLogger();

    private final State state;

    private ResponseFingerprint fingerprint;

    public FingerPrintTask(State state, int reexecutions) {
        super(reexecutions);
        this.state = state;
    }

    public FingerPrintTask(
            State state,
            long additionalSleepTime,
            boolean increasingSleepTimes,
            int reexecutions,
            long additionalTcpTimeout) {
        super(reexecutions, additionalSleepTime, increasingSleepTimes, additionalTcpTimeout);
        this.state = state;
    }

    @Override
    public boolean execute() {
        try {
            WorkflowExecutor executor = getExecutor(state);
            executor.executeWorkflow();

            if (!state.getWorkflowTrace().executedAsPlanned()) {
                return false;
            }
            fingerprint = ResponseExtractor.getFingerprint(state);
            return true;
        } finally {
            try {
                state.getSshContext().getTransportHandler().closeConnection();
            } catch (IOException ex) {
                LOGGER.debug(ex);
            }
        }
    }

    public State getState() {
        return state;
    }

    public ResponseFingerprint getFingerprint() {
        return fingerprint;
    }

    @Override
    public void reset() {
        state.reset();
    }
}
