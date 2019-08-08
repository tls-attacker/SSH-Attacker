package de.rub.nds.sshattacker.workflow.action;

import de.rub.nds.sshattacker.exceptions.WorkflowExecutionException;
import de.rub.nds.sshattacker.state.State;

public class ActivateEncryptionAction extends ConnectionBoundAction {

    @Override
    public void execute(State state) throws WorkflowExecutionException {
        state.getSshContext().setIsEncryptionActive(true);
    }

    @Override
    public void reset() {
    }

    @Override
    public boolean executedAsPlanned() {
        return isExecuted();
    }

}
