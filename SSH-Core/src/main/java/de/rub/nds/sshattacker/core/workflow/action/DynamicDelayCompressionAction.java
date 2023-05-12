/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.workflow.action;

import de.rub.nds.sshattacker.core.exceptions.WorkflowExecutionException;
import de.rub.nds.sshattacker.core.protocol.transport.message.DisconnectMessage;
import de.rub.nds.sshattacker.core.protocol.transport.message.NewCompressMessage;
import de.rub.nds.sshattacker.core.state.SshContext;
import de.rub.nds.sshattacker.core.state.State;
import de.rub.nds.sshattacker.core.workflow.factory.SshActionFactory;
import de.rub.nds.tlsattacker.transport.ConnectionEndType;
import java.util.ArrayList;
import java.util.List;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class DynamicDelayCompressionAction extends SendAction {

    private static final Logger LOGGER = LogManager.getLogger();

    private List<SshAction> sshActions = new ArrayList<>();

    public DynamicDelayCompressionAction() {
        super();
    }

    @Override
    public void execute(State state) throws WorkflowExecutionException {
        if (isExecuted()) {
            throw new WorkflowExecutionException("Action already executed!");
        }

        SshContext context = state.getSshContext();

        // check whether a common compression method could be negotiated
        if (context.getDelayCompressionExtensionNegotiationFailed()) {
            // send DisconnectMessage acting as client
            if (context.isClient()) {
                sshActions.add(
                        SshActionFactory.createMessageAction(
                                context.getConnection(),
                                ConnectionEndType.CLIENT,
                                new DisconnectMessage()));
            }
            // send DisconnectMessage acting as server
            else {
                sshActions.add(
                        SshActionFactory.createMessageAction(
                                context.getConnection(),
                                ConnectionEndType.SERVER,
                                new DisconnectMessage()));
            }
        }

        if (context.delayCompressionExtensionReceived()
                && context.isClient()
                && context.delayCompressionExtensionSent()) {
            sshActions.add(
                    SshActionFactory.createMessageAction(
                            context.getConnection(),
                            ConnectionEndType.CLIENT,
                            new NewCompressMessage()));
            sshActions.forEach(sshAction -> sshAction.execute(state));
        }
    }
}
