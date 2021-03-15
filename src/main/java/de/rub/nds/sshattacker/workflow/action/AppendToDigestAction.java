package de.rub.nds.sshattacker.workflow.action;

import de.rub.nds.sshattacker.exceptions.WorkflowExecutionException;
import de.rub.nds.sshattacker.state.State;

public class AppendToDigestAction extends ConnectionBoundAction {

    private final byte[] data;

    public AppendToDigestAction(byte[] data) {
        this.data = data;
    }

    @Override
    public void execute(State state) throws WorkflowExecutionException {
        state.getSshContext().appendToExchangeHashInput(data);
    }

    @Override
    public void reset() {
    }

    @Override
    public boolean executedAsPlanned() {
        return isExecuted();
    }

}
