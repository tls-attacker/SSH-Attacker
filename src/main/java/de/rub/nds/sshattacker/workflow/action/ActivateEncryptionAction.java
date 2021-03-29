/**
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2021 Ruhr University Bochum, Paderborn University,
 * and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
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
