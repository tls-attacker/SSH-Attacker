/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2021 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.workflow;

import de.rub.nds.sshattacker.core.constants.MessageIDConstant;
import de.rub.nds.sshattacker.core.protocol.common.ProtocolMessage;
import de.rub.nds.sshattacker.core.protocol.common.SshMessage;
import de.rub.nds.sshattacker.core.protocol.transport.message.BinaryPacket;
import de.rub.nds.sshattacker.core.workflow.action.ReceivingAction;
import de.rub.nds.sshattacker.core.workflow.action.SendingAction;
import java.util.LinkedList;
import java.util.List;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class WorkflowTraceUtil {

    private static final Logger LOGGER = LogManager.getLogger();

    public static List<ProtocolMessage<?>> getAllSendMessages(WorkflowTrace trace) {
        List<ProtocolMessage<?>> sendMessages = new LinkedList<>();
        for (SendingAction action : trace.getSendingActions()) {
            sendMessages.addAll(action.getSendMessages());
        }
        return sendMessages;
    }

    public static List<BinaryPacket> getAllSendBinaryPackets(WorkflowTrace trace) {
        List<BinaryPacket> sendBinaryPackets = new LinkedList<>();
        for (SendingAction action : trace.getSendingActions()) {
            sendBinaryPackets.addAll(action.getSendBinaryPackets());
        }
        return sendBinaryPackets;
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
            WorkflowTrace trace, MessageIDConstant type) {
        List<ProtocolMessage<?>> receivedMessage = new LinkedList<>();
        for (ProtocolMessage<?> message : getAllReceivedMessages(trace)) {
            if (message instanceof SshMessage<?>
                    && ((SshMessage<?>) message).getMessageID().getValue() == type.id) {
                receivedMessage.add(message);
            }
        }
        return receivedMessage;
    }

    private WorkflowTraceUtil() {}
}
