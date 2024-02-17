/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.workflow;

import de.rub.nds.sshattacker.core.constants.MessageIdConstant;
import de.rub.nds.sshattacker.core.packet.AbstractPacket;
import de.rub.nds.sshattacker.core.protocol.common.ProtocolMessage;
import de.rub.nds.sshattacker.core.protocol.common.SshMessage;
import de.rub.nds.sshattacker.core.workflow.action.ReceivingAction;
import de.rub.nds.sshattacker.core.workflow.action.SendingAction;
import java.util.LinkedList;
import java.util.List;
import java.util.stream.Collectors;

public final class WorkflowTraceUtil {

    public static List<ProtocolMessage<?>> getAllSendMessages(WorkflowTrace trace) {
        List<ProtocolMessage<?>> sendMessages = new LinkedList<>();
        for (SendingAction action : trace.getSendingActions()) {
            sendMessages.addAll(action.getSendMessages());
        }
        return sendMessages;
    }

    public static List<ProtocolMessage<?>> getAllReceivedMessages(WorkflowTrace trace) {
        List<ProtocolMessage<?>> receivedMessage = new LinkedList<>();
        for (ReceivingAction action : trace.getReceivingActions()) {
            if (action.getReceivedMessages() != null) {
                receivedMessage.addAll(action.getReceivedMessages());
            }
        }
        return receivedMessage;
    }

    public static List<ProtocolMessage<?>> getAllReceivedMessages(
            WorkflowTrace trace, MessageIdConstant type) {
        List<ProtocolMessage<?>> receivedMessage = new LinkedList<>();
        for (ProtocolMessage<?> message : getAllReceivedMessages(trace)) {
            if (message instanceof SshMessage<?>
                    && ((SshMessage<?>) message).getMessageId().getValue() == type.getId()) {
                receivedMessage.add(message);
            }
        }
        return receivedMessage;
    }

    public static List<AbstractPacket> getAllReceivedPackets(WorkflowTrace trace) {
        return getAllReceivedPackets(trace, AbstractPacket.class);
    }

    public static <T extends AbstractPacket> List<T> getAllReceivedPackets(
            WorkflowTrace trace, Class<T> packetClass) {
        //noinspection unchecked
        return trace.getReceivingActions().stream()
                .flatMap(action -> action.getReceivedPackets().stream())
                .filter(packetClass::isInstance)
                .map(packet -> (T) packet)
                .collect(Collectors.toUnmodifiableList());
    }

    private WorkflowTraceUtil() {
        super();
    }
}
