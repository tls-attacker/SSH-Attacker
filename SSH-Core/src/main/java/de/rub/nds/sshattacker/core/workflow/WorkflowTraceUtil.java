/**
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * <p>Copyright 2014-2021 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * <p>Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.workflow;

import de.rub.nds.sshattacker.core.constants.MessageIDConstant;
import de.rub.nds.sshattacker.core.protocol.common.Message;
import de.rub.nds.sshattacker.core.protocol.transport.message.BinaryPacket;
import de.rub.nds.sshattacker.core.workflow.action.ReceivingAction;
import de.rub.nds.sshattacker.core.workflow.action.SendingAction;
import java.util.LinkedList;
import java.util.List;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class WorkflowTraceUtil {

    private static final Logger LOGGER = LogManager.getLogger();

    public static List<Message<?>> getAllSendMessages(WorkflowTrace trace) {
        List<Message<?>> sendMessages = new LinkedList<>();
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

    public static List<Message<?>> getAllReceivedMessages(WorkflowTrace trace) {
        List<Message<?>> receivedMessage = new LinkedList<>();
        for (ReceivingAction action : trace.getReceivingActions()) {
            if (action.getReceivedMessages() != null) {
                receivedMessage.addAll(action.getReceivedMessages());
            }
        }
        return receivedMessage;
    }

    public static List<Message<?>> getAllReceivedMessages(
            WorkflowTrace trace, MessageIDConstant type) {
        List<Message<?>> receivedMessage = new LinkedList<>();
        for (Message<?> message : getAllReceivedMessages(trace)) {
            if (message.getMessageID().getValue() == type.id) {
                receivedMessage.add(message);
            }
        }
        return receivedMessage;
    }

    private WorkflowTraceUtil() {}
}
