/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.workflow;

import de.rub.nds.sshattacker.core.state.State;
import de.rub.nds.sshattacker.core.workflow.action.executor.WorkflowExecutorType;

public final class WorkflowExecutorFactory {

    public static WorkflowExecutor createWorkflowExecutor(WorkflowExecutorType type, State state) {
        switch (type) {
            case DEFAULT:
                return new DefaultWorkflowExecutor(state);
            case THREADED_SERVER:
                return new ThreadedServerWorkflowExecutor(state);
            default:
                throw new UnsupportedOperationException(type.name() + " not yet implemented");
        }
    }

    private WorkflowExecutorFactory() {
        super();
    }
}
