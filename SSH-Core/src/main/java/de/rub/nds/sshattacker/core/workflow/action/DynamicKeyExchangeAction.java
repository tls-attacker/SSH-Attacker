/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.workflow.action;

import de.rub.nds.sshattacker.core.connection.AliasedConnection;
import de.rub.nds.sshattacker.core.constants.KeyExchangeAlgorithm;
import de.rub.nds.sshattacker.core.exceptions.WorkflowExecutionException;
import de.rub.nds.sshattacker.core.state.SshContext;
import de.rub.nds.sshattacker.core.state.State;
import de.rub.nds.sshattacker.core.workflow.factory.WorkflowConfigurationFactory;

public class DynamicKeyExchangeAction extends DynamicMessageAction {

    public DynamicKeyExchangeAction() {
        super(AliasedConnection.DEFAULT_CONNECTION_ALIAS);
    }

    public DynamicKeyExchangeAction(String connectionAlias) {
        super(connectionAlias);
    }

    public DynamicKeyExchangeAction(DynamicKeyExchangeAction other) {
        super(other);
    }

    @Override
    public DynamicKeyExchangeAction createCopy() {
        return new DynamicKeyExchangeAction(this);
    }

    @Override
    public void execute(State state) throws WorkflowExecutionException {
        if (isExecuted()) {
            throw new WorkflowExecutionException("Action already executed!");
        }

        SshContext context = state.getSshContext(connectionAlias);
        KeyExchangeAlgorithm keyExchangeAlgorithm = context.getChooser().getKeyExchangeAlgorithm();
        sshActions =
                WorkflowConfigurationFactory.createKeyExchangeActions(
                        keyExchangeAlgorithm.getFlowType(), context.getConnection());
        sshActions.forEach(sshAction -> sshAction.execute(state));
        setExecuted(true);
    }
}
