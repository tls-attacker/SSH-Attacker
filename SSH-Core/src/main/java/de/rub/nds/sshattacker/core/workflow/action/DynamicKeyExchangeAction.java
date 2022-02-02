/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2021 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
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
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class DynamicKeyExchangeAction extends MessageAction {

    private static final Logger LOGGER = LogManager.getLogger();
    private List<SshAction> sshActions = new ArrayList<>();

    public DynamicKeyExchangeAction() {
        super(AliasedConnection.DEFAULT_CONNECTION_ALIAS);
    }

    public DynamicKeyExchangeAction(String connectionAlias) {
        super(connectionAlias);
    }

    @Override
    public void execute(State state) throws WorkflowExecutionException {
        SshContext context = state.getSshContext(connectionAlias);
        WorkflowConfigurationFactory factory =
                new WorkflowConfigurationFactory(context.getConfig());
        KeyExchangeAlgorithm choosenKeyExchangeAlgortihm = context.getKeyExchangeAlgorithm().get();

        if (isExecuted()) {
            throw new WorkflowExecutionException("Action already executed!");
        }

        if (choosenKeyExchangeAlgortihm == null) {
            throw new WorkflowExecutionException(
                    "Missing choosen KeyExchangeAlgorithm, required for DynamicKeyExchangeAction. Some failure in KeyExchangeInit handling!");
        }
        sshActions =
                factory.createKeyExchangeActions(
                        choosenKeyExchangeAlgortihm, context.getConnection());
        sshActions.forEach(sshAction -> sshAction.execute(state));
    }

    @Override
    public void reset() {
        for (SshAction action : sshActions) {
            action.reset();
        }
    }

    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder();
        for (SshAction sshAction : sshActions) {
            sb.append(sshAction.toString());
            sb.append("\n");
        }
        return super.toString();
    }

    @Override
    public boolean executedAsPlanned() {
        return isExecuted();
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        if (!super.equals(o)) return false;
        DynamicKeyExchangeAction that = (DynamicKeyExchangeAction) o;
        return Objects.equals(sshActions, that.sshActions);
    }

    @Override
    public int hashCode() {
        int hash = 5;
        hash = 79 * hash + Objects.hash(super.hashCode(), sshActions);
        return hash;
    }
}
