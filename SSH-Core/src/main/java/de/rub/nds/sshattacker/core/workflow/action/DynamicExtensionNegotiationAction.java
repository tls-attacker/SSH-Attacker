/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.workflow.action;

import de.rub.nds.sshattacker.core.exceptions.WorkflowExecutionException;
import de.rub.nds.sshattacker.core.protocol.transport.message.ExtensionInfoMessage;
import de.rub.nds.sshattacker.core.state.SshContext;
import de.rub.nds.sshattacker.core.state.State;
import de.rub.nds.sshattacker.core.workflow.factory.SshActionFactory;
import de.rub.nds.tlsattacker.transport.ConnectionEndType;

public class DynamicExtensionNegotiationAction extends DynamicMessageAction {

    public DynamicExtensionNegotiationAction() {
        super();
    }

    public DynamicExtensionNegotiationAction(String connectionAlias) {
        super(connectionAlias);
    }

    @Override
    public void execute(State state) throws WorkflowExecutionException {
        if (isExecuted()) {
            throw new WorkflowExecutionException("Action already executed!");
        }

        SshContext context = state.getSshContext(connectionAlias);

        if (context.clientSupportsExtensionNegotiation() && !context.isClient()) {
            sshActions.add(
                    SshActionFactory.createMessageAction(
                            context.getConnection(),
                            ConnectionEndType.SERVER,
                            new ExtensionInfoMessage()));
            sshActions.forEach(sshAction -> sshAction.execute(state));
        } else if (context.serverSupportsExtensionNegotiation() && context.isClient()) {
            sshActions.add(
                    SshActionFactory.createMessageAction(
                            context.getConnection(),
                            ConnectionEndType.CLIENT,
                            new ExtensionInfoMessage()));
            sshActions.forEach(sshAction -> sshAction.execute(state));
        }
        setExecuted(true);
    }
}
