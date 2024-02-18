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
import de.rub.nds.sshattacker.core.workflow.action.ReceivingAction;
import de.rub.nds.sshattacker.core.workflow.action.SendingAction;
import de.rub.nds.sshattacker.core.workflow.action.SshAction;
import java.util.LinkedList;
import java.util.List;
import java.util.stream.Collectors;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public final class WorkflowTraceUtil {

    private static final Logger LOGGER = LogManager.getLogger();

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

    public static ProtocolMessage getFirstReceivedMessage(WorkflowTrace trace) {
        List<ProtocolMessage> messageList = getAllReceivedMessages(trace);
        if (messageList.isEmpty()) {
            return null;
        } else {
            return messageList.get(0);
        }
    }

    public static ProtocolMessage getLastReceivedMessage(WorkflowTrace trace) {
        List<ProtocolMessage> messageList = getAllReceivedMessages(trace);
        if (messageList.isEmpty()) {
            return null;
        } else {
            return messageList.get(messageList.size() - 1);
        }
    }

    public static ProtocolMessage getFirstSendMessage(WorkflowTrace trace) {
        List<ProtocolMessage> messageList = getAllSendMessages(trace);
        if (messageList.isEmpty()) {
            return null;
        } else {
            return messageList.get(0);
        }
    }

    public static SshAction getFirstFailedAction(WorkflowTrace trace) {
        for (SshAction action : trace.getSshActions()) {
            if (!action.executedAsPlanned()) {
                return action;
            }
        }
        return null;
    }

    public static ProtocolMessage getLastSendMessage(WorkflowTrace trace) {
        List<ProtocolMessage> messageList = getAllSendMessages(trace);
        if (messageList.isEmpty()) {
            return null;
        } else {
            return messageList.get(messageList.size() - 1);
        }
    }

    public static List<ProtocolMessage> getAllReceivedMessages(WorkflowTrace trace) {
        List<ProtocolMessage> receivedMessage = new LinkedList<>();
        for (ReceivingAction action : trace.getReceivingActions()) {
            if (action.getReceivedMessages() != null) {
                receivedMessage.addAll(action.getReceivedMessages());
            }
        }
        return receivedMessage;
    }

    public static List<ProtocolMessage> getAllReceivedMessages(
            WorkflowTrace trace, MessageIdConstant type) {
        List<ProtocolMessage> receivedMessage = new LinkedList<>();
        for (ProtocolMessage message : getAllReceivedMessages(trace)) {
            if (message.getMessageIdConstant() == type) {
                receivedMessage.add(message);
            }
        }
        return receivedMessage;
    }

    public static List<ProtocolMessage> getAllSendMessages(WorkflowTrace trace) {
        List<ProtocolMessage> sendMessages = new LinkedList<>();
        for (SendingAction action : trace.getSendingActions()) {
            sendMessages.addAll(action.getSendMessages());
        }
        return sendMessages;
    }

    public static SendingAction getLastSendingAction(WorkflowTrace trace) {
        List<SendingAction> sendingActions = trace.getSendingActions();
        return sendingActions.get(sendingActions.size() - 1);
    }

    public static SshAction getLaterAction(
            WorkflowTrace trace, SshAction action1, SshAction action2) {
        if ((action1 == null && action2 == null)
                || (!containsIdenticalAction(trace, action1)
                        && !containsIdenticalAction(trace, action2))) {
            return null;
        } else if (action1 == null || !containsIdenticalAction(trace, action1)) {
            return action2;
        } else if (action2 == null || !containsIdenticalAction(trace, action2)) {
            return action1;
        }

        return indexOfIdenticalAction(trace, action1) > indexOfIdenticalAction(trace, action2)
                ? action1
                : action2;
    }

    public static SshAction getEarlierAction(
            WorkflowTrace trace, SshAction action1, SshAction action2) {
        if ((action1 == null && action2 == null)
                || (!containsIdenticalAction(trace, action1)
                        && !containsIdenticalAction(trace, action2))) {
            return null;
        } else if (action1 == null || !containsIdenticalAction(trace, action1)) {
            return action2;
        } else if (action2 == null || !containsIdenticalAction(trace, action2)) {
            return action1;
        }

        return indexOfIdenticalAction(trace, action1) < indexOfIdenticalAction(trace, action2)
                ? action1
                : action2;
    }

    /*
        public static List<MessageAction> getMessageActionsWithUnreadBytes(
                @Nonnull WorkflowTrace trace) {
            List<MessageAction> messageActionsWithUnreadBytes = new LinkedList<>();
            for (SshAction action : trace.getSshActions()) {
                if (action instanceof MessageAction
                        && action instanceof ReceivingAction
                        && ((MessageAction) action).getLayerStackProcessingResult() != null
                        && ((MessageAction) action).getLayerStackProcessingResult().hasUnreadBytes()) {
                    messageActionsWithUnreadBytes.add((MessageAction) action);
                }
            }
            return messageActionsWithUnreadBytes;
        }
    */
    /*

        public static boolean hasUnreadBytes(@Nonnull WorkflowTrace trace) {
            return !(getMessageActionsWithUnreadBytes(trace).isEmpty());
        }
    */

    public static int indexOfIdenticalAction(WorkflowTrace trace, SshAction action) {
        if (trace.getSshActions() != null) {
            for (int i = 0; i < trace.getSshActions().size(); i++) {
                if (trace.getSshActions().get(i) == action) {
                    return i;
                }
            }
        }
        return -1;
    }

    public static boolean containsIdenticalAction(WorkflowTrace trace, SshAction action) {
        if (trace.getSshActions() != null) {
            return trace.getSshActions().stream().anyMatch(listed -> listed == action);
        }
        return false;
    }

    private WorkflowTraceUtil() {}
}
