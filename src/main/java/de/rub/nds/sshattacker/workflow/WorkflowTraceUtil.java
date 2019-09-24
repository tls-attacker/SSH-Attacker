/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.workflow;

import de.rub.nds.sshattacker.constants.MessageIDConstant;
import de.rub.nds.sshattacker.protocol.message.BinaryPacket;
import de.rub.nds.sshattacker.protocol.message.Message;
import de.rub.nds.sshattacker.workflow.action.ReceivingAction;
import de.rub.nds.sshattacker.workflow.action.SendingAction;
import java.util.LinkedList;
import java.util.List;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class WorkflowTraceUtil {

    private static final Logger LOGGER = LogManager.getLogger();

    public static List<Message> getAllSendMessages(WorkflowTrace trace) {
        List<Message> sendMessages = new LinkedList<>();
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

    public static List<Message> getAllReceivedMessages(WorkflowTrace trace) {
        List<Message> receivedMessage = new LinkedList<>();
        for (ReceivingAction action : trace.getReceivingActions()) {
            if (action.getReceivedMessages() != null) {
                receivedMessage.addAll(action.getReceivedMessages());
            }
        }
        return receivedMessage;
    }

    public static List<Message> getAllReceivedMessages(WorkflowTrace trace, MessageIDConstant type) {
        List<Message> receivedMessage = new LinkedList<>();
        for (Message message : getAllReceivedMessages(trace)) {
            if (message.getMessageID().getValue() == type.id) {
                receivedMessage.add(message);
            }
        }
        return receivedMessage;
    }

    private WorkflowTraceUtil() {
    }

}
