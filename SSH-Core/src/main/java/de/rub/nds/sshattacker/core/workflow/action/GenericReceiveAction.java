/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2021 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.workflow.action;

import de.rub.nds.sshattacker.core.exceptions.WorkflowExecutionException;
import de.rub.nds.sshattacker.core.protocol.common.ProtocolMessage;
import de.rub.nds.sshattacker.core.protocol.transport.message.BinaryPacket;
import de.rub.nds.sshattacker.core.state.SshContext;
import de.rub.nds.sshattacker.core.state.State;
import de.rub.nds.sshattacker.core.workflow.action.executor.MessageActionResult;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedList;
import java.util.List;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class GenericReceiveAction extends MessageAction implements ReceivingAction {

    private static final Logger LOGGER = LogManager.getLogger();

    public GenericReceiveAction() {
        super();
    }

    public GenericReceiveAction(List<ProtocolMessage<?>> messages) {
        super(messages);
    }

    public GenericReceiveAction(ProtocolMessage<?>... messages) {
        this(new ArrayList<>(Arrays.asList(messages)));
    }

    public GenericReceiveAction(String connectionAlias) {
        super(connectionAlias);
    }

    public GenericReceiveAction(String connectionAlias, List<ProtocolMessage<?>> messages) {
        super(connectionAlias, messages);
    }

    public GenericReceiveAction(String connectionAlias, ProtocolMessage<?>... messages) {
        super(connectionAlias, new ArrayList<>(Arrays.asList(messages)));
    }

    @Override
    public void execute(State state) {
        if (isExecuted()) {
            throw new WorkflowExecutionException("Action already executed!");
        }
        LOGGER.debug("Receiving Messages...");
        SshContext ctx = state.getSshContext(getConnectionAlias());
        MessageActionResult result = receiveMessageHelper.receiveMessages(ctx);
        binaryPackets.addAll(result.getBinaryPacketList());
        messages.addAll(result.getMessageList());
        LOGGER.debug("Received MessageAction: " + result);
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
        binaryPackets = new LinkedList<>();
        setExecuted(Boolean.FALSE);
    }

    @Override
    public List<ProtocolMessage<?>> getReceivedMessages() {
        return messages;
    }

    @Override
    public List<BinaryPacket> getReceivedBinaryPackets() {
        return binaryPackets;
    }
}
