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

import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.function.Predicate;

public class DynamicKeyExchangeAction extends MessageAction {

    private List<SshAction> sshActions = new ArrayList<>();

    public DynamicKeyExchangeAction() {
        super(AliasedConnection.DEFAULT_CONNECTION_ALIAS);
    }

    public DynamicKeyExchangeAction(String connectionAlias) {
        super(connectionAlias);
    }

    @Override
    public void execute(State state) throws WorkflowExecutionException {
        if (isExecuted()) {
            throw new WorkflowExecutionException("Action already executed!");
        }

        SshContext context = state.getSshContext(connectionAlias);
        WorkflowConfigurationFactory factory =
                new WorkflowConfigurationFactory(context.getConfig());
        KeyExchangeAlgorithm keyExchangeAlgorithm = context.getChooser().getKeyExchangeAlgorithm();
        sshActions =
                factory.createKeyExchangeActions(
                        keyExchangeAlgorithm.getFlowType(), context.getConnection());
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
        return sb.toString();
    }

    @Override
    public boolean isExecuted() {
        // This action can only contain other ssh actions if it was actually
        // executed.
        return !this.sshActions.isEmpty();
    }

    @Override
    public boolean executedAsPlanned() {
        // Return true if this action was executed and all contained ssh
        // actions were executed as planned.
        return this.isExecuted()
                && this.sshActions.stream()
                        .map(SshAction::executedAsPlanned)
                        .filter(Predicate.isEqual(false))
                        .findAny()
                        .isEmpty();
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
