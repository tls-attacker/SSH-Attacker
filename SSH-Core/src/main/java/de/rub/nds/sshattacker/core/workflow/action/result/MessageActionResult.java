/**
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2021 Ruhr University Bochum, Paderborn University,
 * and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.workflow.action.result;

import de.rub.nds.sshattacker.core.protocol.message.BinaryPacket;
import de.rub.nds.sshattacker.core.protocol.message.Message;
import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedList;
import java.util.List;

public class MessageActionResult {

    private final List<BinaryPacket> binaryPacketList;

    private final List<Message<?>> messageList;

    public MessageActionResult(List<BinaryPacket> binaryPacketList, List<Message<?>> messageList) {
        this.binaryPacketList = binaryPacketList;
        this.messageList = messageList;
    }

    /**
     * Generates an empty MessageActionResult, that is, a result whose list fields are empty.
     */
    public MessageActionResult() {
        this(new LinkedList<>(), new LinkedList<>());
    }

    public List<BinaryPacket> getBinaryPacketList() {
        return binaryPacketList;
    }

    public List<Message<?>> getMessageList() {
        return messageList;
    }

    /**
     * Merger this with other results, forming a new result.
     */
    public MessageActionResult merge(MessageActionResult... other) {
        LinkedList<MessageActionResult> results = new LinkedList<>(Collections.singletonList(this));
        results.addAll(Arrays.asList(other));
        List<BinaryPacket> binaryPacketList = new LinkedList<>();
        List<Message<?>> messageList = new LinkedList<>();

        for (MessageActionResult result : results) {
            binaryPacketList.addAll(result.getBinaryPacketList());
            messageList.addAll(result.getMessageList());
        }

        return new MessageActionResult(binaryPacketList, messageList);
    }
}
