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
import java.util.ArrayList;
import java.util.List;

public class MessageActionResult {

    private final ArrayList<AbstractPacket> packetList;

    private final ArrayList<ProtocolMessage<?>> messageList;

    public MessageActionResult(
            ArrayList<AbstractPacket> packetList, ArrayList<ProtocolMessage<?>> messageList) {
        super();
        this.packetList = packetList;
        this.messageList = messageList;
    }

    public MessageActionResult(List<MessageActionResult> results) {
        super();
        packetList = new ArrayList<>();
        messageList = new ArrayList<>();

        for (MessageActionResult result : results) {
            packetList.addAll(result.packetList);
            messageList.addAll(result.messageList);
        }
    }

    /** Generates an empty MessageActionResult, that is, a result whose list fields are empty. */
    public MessageActionResult() {
        this(new ArrayList<>(), new ArrayList<>());
    }

    public ArrayList<AbstractPacket> getPacketList() {
        return packetList;
    }

    public ArrayList<ProtocolMessage<?>> getMessageList() {
        return messageList;
    }

    /**
     * Merge this {@code MessageActionResult} with other results. The resulting MessageActionResult
     * will be a combination of both, message and packet lists.
     *
     * @param others Multiple other {@code MessageActionResult} objects to join this to.
     * @return An accumulated {@code MessageActionResult} object containing all messages and packets
     *     from this and other.
     */
    public MessageActionResult merge(MessageActionResult... others) {
        ArrayList<AbstractPacket> packetList = new ArrayList<>(this.packetList);
        ArrayList<ProtocolMessage<?>> messageList = new ArrayList<>(this.messageList);

        for (MessageActionResult result : others) {
            packetList.addAll(result.packetList);
            messageList.addAll(result.messageList);
        }

        return new MessageActionResult(packetList, messageList);
    }
}
