/**
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2021 Ruhr University Bochum, Paderborn University,
 * and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.layers;

import de.rub.nds.sshattacker.core.protocol.message.BinaryPacket;
import de.rub.nds.sshattacker.core.protocol.message.Message;
import de.rub.nds.sshattacker.core.protocol.parser.MessageParser;
import de.rub.nds.sshattacker.core.protocol.serializer.MessageSerializer;
import de.rub.nds.sshattacker.core.state.SshContext;
import java.util.ArrayList;
import java.util.List;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class MessageLayer {

    private static final Logger LOGGER = LogManager.getLogger();
    private final SshContext context;

    public MessageLayer(SshContext context) {
        this.context = context;
    }

    public List<Message<?>> parseMessages(List<BinaryPacket> list) {
        List<Message<?>> returnList = new ArrayList<>();
        for (BinaryPacket packet : list) {
            Message<?> msg = MessageParser.delegateParsing(packet.getPayload().getValue(), context);
            returnList.add(msg);
        }
        return returnList;
    }

    public BinaryPacket serializeMessage(Message<?> msg) {
        BinaryPacket packet = new BinaryPacket();
        byte[] payload = MessageSerializer.delegateSerialization(msg);
        packet.setPayload(payload);
        byte blocksize = 8;
        if (context.getCipherAlgorithmClientToServer() != null) {
            blocksize = (byte) context.getCipherAlgorithmClientToServer().getBlockSize();
        }
        packet.computePaddingLength(blocksize);
        packet.generatePadding();
        packet.computePacketLength();
        return packet;
    }

    public List<BinaryPacket> serializeMessages(List<Message<?>> list) {
        List<BinaryPacket> returnList = new ArrayList<>();
        for (Message<?> msg : list) {
            BinaryPacket packet = serializeMessage(msg);
            returnList.add(packet);
        }
        return returnList;
    }
}
