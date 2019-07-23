/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.workflow.action.executor;

import de.rub.nds.sshattacker.protocol.message.BinaryPacket;
import de.rub.nds.sshattacker.protocol.message.Message;
import java.util.Arrays;
import java.util.LinkedList;
import java.util.List;

public class MessageActionResult {

    private final List<BinaryPacket> binaryPacketList;

    private final List<Message> messageList;

    public MessageActionResult(List<BinaryPacket> binaryPacketList, List<Message> messageList) {
        this.binaryPacketList = binaryPacketList;
        this.messageList = messageList;
    }

    /**
     * Generates an empty MessageActionResult, that is, a result whose list
     * fields are empty.
     */
    public MessageActionResult() {
        this(new LinkedList<BinaryPacket>(), new LinkedList<Message>());
    }

    public List<BinaryPacket> getBinaryPacketList() {
        return binaryPacketList;
    }

    public List<Message> getMessageList() {
        return messageList;
    }

    /**
     * Merger this with other results, forming a new result.
     */
    public MessageActionResult merge(MessageActionResult... other) {
        LinkedList<MessageActionResult> results = new LinkedList<MessageActionResult>(Arrays.asList(other));
        results.add(0, this);
        List<BinaryPacket> binaryPacketList = new LinkedList<>();
        List<Message> messageList = new LinkedList<>();

        for (MessageActionResult result : results) {
            binaryPacketList.addAll(result.getBinaryPacketList());
            messageList.addAll(result.getMessageList());
        }

        return new MessageActionResult(binaryPacketList, messageList);
    }
}
