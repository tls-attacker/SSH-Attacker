/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.attacks.task;

import de.rub.nds.sshattacker.core.state.State;
import de.rub.nds.sshattacker.core.workflow.WorkflowExecutor;

/** Do not use this Task if you want to rely on the socket state */
public class StateExecutionTask extends SshTask {

    private final State state;

    public StateExecutionTask(State state, int reexecutions) {
        super(reexecutions);
        this.state = state;
    }

    @Override
    public boolean execute() {
        WorkflowExecutor executor = getExecutor(state);
        executor.executeWorkflow();
        return true;
    }

    public State getState() {
        return state;
    }

    @Override
    public void reset() {
        state.reset();
    }
}
