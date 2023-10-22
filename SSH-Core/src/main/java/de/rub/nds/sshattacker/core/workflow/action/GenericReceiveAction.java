/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.workflow.action;

import de.rub.nds.sshattacker.core.exceptions.ActionExecutionException;
import de.rub.nds.sshattacker.core.layer.context.SshContext;
import de.rub.nds.sshattacker.core.protocol.common.ProtocolMessage;
import de.rub.nds.sshattacker.core.state.State;
import jakarta.xml.bind.annotation.XmlRootElement;
import java.util.LinkedList;
import java.util.List;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

@XmlRootElement
public class GenericReceiveAction extends MessageAction implements ReceivingAction {

    private static final Logger LOGGER = LogManager.getLogger();

    public GenericReceiveAction() {
        super();
    }

    public GenericReceiveAction(String connectionAlias) {
        super(connectionAlias);
    }

    @Override
    public void execute(State state) {
        if (isExecuted()) {
            throw new ActionExecutionException("Action already executed!");
        }
        LOGGER.debug("Receiving Messages...");
        SshContext ctx = state.getContext(getConnectionAlias()).getSshContext();
        receive(ctx, null, null);

        setExecuted(true);
        String received = getReadableString(messages);
        LOGGER.info("Received Messages (" + ctx + "): " + received);
    }

    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder("Receive Action:\n");
        sb.append("\tActual:");
        for (ProtocolMessage<?> message : messages) {
            sb.append(message.toCompactString());
            sb.append(", ");
        }
        return sb.toString();
    }

    @Override
    public boolean executedAsPlanned() {
        return isExecuted();
    }

    @Override
    public void reset() {
        messages = new LinkedList<>();
        setExecuted(null);
    }

    @Override
    public List<ProtocolMessage<?>> getReceivedMessages() {
        return messages;
    }
}
