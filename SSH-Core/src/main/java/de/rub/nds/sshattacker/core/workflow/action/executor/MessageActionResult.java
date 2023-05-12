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

public class MessageActionResult {

    private final List<AbstractPacket> packetList;

    private final List<ProtocolMessage<?>> messageList;

    public MessageActionResult(
            List<AbstractPacket> packetList, List<ProtocolMessage<?>> messageList) {
        super();
        this.packetList = packetList;
        this.messageList = messageList;
    }

    /** Generates an empty MessageActionResult, that is, a result whose list fields are empty. */
    public MessageActionResult() {
        this(new LinkedList<>(), new LinkedList<>());
    }

    public List<AbstractPacket> getPacketList() {
        return packetList;
    }

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
