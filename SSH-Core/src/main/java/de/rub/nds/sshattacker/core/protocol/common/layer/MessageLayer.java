/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2021 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.common.layer;

import de.rub.nds.sshattacker.core.constants.PacketLayerType;
import de.rub.nds.sshattacker.core.packet.AbstractPacket;
import de.rub.nds.sshattacker.core.packet.BinaryPacket;
import de.rub.nds.sshattacker.core.packet.BlobPacket;
import de.rub.nds.sshattacker.core.protocol.common.ProtocolMessage;
import de.rub.nds.sshattacker.core.protocol.common.ProtocolMessageParser;
import de.rub.nds.sshattacker.core.state.SshContext;
import java.util.stream.Stream;

public class MessageLayer {

    private final SshContext context;

    public MessageLayer(SshContext context) {
        this.context = context;
    }

    public ProtocolMessage<?> parse(AbstractPacket packet) {
        return ProtocolMessageParser.delegateParsing(packet, context);
    }

    public Stream<ProtocolMessage<?>> parse(Stream<AbstractPacket> packetStream) {
        return packetStream.map(this::parse);
    }

    public AbstractPacket serialize(ProtocolMessage<?> message) {
        AbstractPacket packet;
        if (context.getPacketLayerType() == PacketLayerType.BLOB) {
            packet = new BlobPacket();
        } else {
            packet = new BinaryPacket();
        }
        packet.setPayload(message.getHandler(context).getSerializer().serialize());
        return packet;
    }

    public Stream<AbstractPacket> serialize(Stream<ProtocolMessage<?>> messageStream) {
        return messageStream.map(this::serialize);
    }
}
