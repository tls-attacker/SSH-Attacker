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
import java.util.LinkedList;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class DynamicExtensionNegotiationAction extends SendAction {

    private static final Logger LOGGER = LogManager.getLogger();

    public DynamicExtensionNegotiationAction() {
        super();
    }

    public DynamicExtensionNegotiationAction(String connectionAlias) {
        super(connectionAlias);
    }

    @Override
    public void execute(State state) throws WorkflowExecutionException {
        SshContext context = state.getSshContext();
        messages = new LinkedList<>();
        if (context.clientSupportsExtensionNegotiation()) {
            ExtensionInfoMessage msg = new ExtensionInfoMessage();
            msg.setExtensionCount(context.getChooser().getServerSupportedExtensions().size());
            msg.setExtensions(context.getChooser().getServerSupportedExtensions());
            messages.add(msg);
        } else if (context.serverSupportsExtensionNegotiation()) {
            ExtensionInfoMessage msg = new ExtensionInfoMessage();
            msg.setExtensionCount(context.getChooser().getClientSupportedExtensions().size());
            msg.setExtensions(context.getChooser().getClientSupportedExtensions());
            messages.add(msg);
        }
        super.execute(state);
    }
}
