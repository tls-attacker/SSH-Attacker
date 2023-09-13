/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.workflow.action.executor;

import de.rub.nds.sshattacker.core.packet.AbstractPacket;
import de.rub.nds.sshattacker.core.protocol.common.ProtocolMessage;
import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedList;
import java.util.List;

/**
 * The result of a {@link SendMessageHelper#sendMessage} call. Contains the sent packets and
 * messages.
 */
public class MessageActionResult {

    private final List<AbstractPacket> packetList;

    private final List<ProtocolMessage<?>> messageList;

    /**
     * Generates a MessageActionResult with the given packet and message lists.
     *
     * @param packetList The list of packets that were sent.
     * @param messageList The list of messages that were sent.
     */
    public MessageActionResult(
            List<AbstractPacket> packetList, List<ProtocolMessage<?>> messageList) {
        super();
        this.packetList = packetList;
        this.messageList = messageList;
    }

    /** Generates a MessageActionResult with empty packet and message lists. */
    public MessageActionResult() {
        this(new LinkedList<>(), new LinkedList<>());
    }

    /**
     * @return The list of packets that were sent.
     */
    public List<AbstractPacket> getPacketList() {
        return packetList;
    }

    /**
     * @return The list of messages that were sent.
     */
    public List<ProtocolMessage<?>> getMessageList() {
        return messageList;
    }

    /**
     * Merge this {@code MessageActionResult} with other results. The resulting MessageActionResult
     * will be a combination of both, message and packet lists.
     *
     * @param other Multiple other {@code MessageActionResult} objects to join this to.
     * @return An accumulated {@code MessageActionResult} object containing all messages and packets
     *     from this and other.
     */
    public MessageActionResult merge(MessageActionResult... other) {
        LinkedList<MessageActionResult> results = new LinkedList<>(Collections.singletonList(this));
        results.addAll(Arrays.asList(other));
        List<AbstractPacket> packetList = new LinkedList<>();
        List<ProtocolMessage<?>> messageList = new LinkedList<>();

        for (MessageActionResult result : results) {
            packetList.addAll(result.packetList);
            messageList.addAll(result.messageList);
        }

        return new MessageActionResult(packetList, messageList);
    }
}
