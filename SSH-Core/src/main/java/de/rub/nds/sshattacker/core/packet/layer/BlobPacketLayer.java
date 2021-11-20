/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2021 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.packet.layer;

import de.rub.nds.sshattacker.core.exceptions.ParserException;
import de.rub.nds.sshattacker.core.packet.AbstractPacket;
import de.rub.nds.sshattacker.core.packet.BlobPacket;
import de.rub.nds.sshattacker.core.packet.parser.BlobPacketParser;
import de.rub.nds.sshattacker.core.state.SshContext;
import java.util.stream.Stream;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class BlobPacketLayer extends AbstractPacketLayer {

    private static final Logger LOGGER = LogManager.getLogger();

    public BlobPacketLayer(SshContext context) {
        super(context);
    }

    @Override
    public Stream<AbstractPacket> parsePackets(byte[] rawBytes) throws ParserException {
        Stream.Builder<AbstractPacket> packetStreamBuilder = Stream.builder();
        try {
            BlobPacketParser parser = new BlobPacketParser(rawBytes, 0);
            BlobPacket packet = parser.parse();
            decryptPacket(packet);
            packetStreamBuilder.add(packet);
            return packetStreamBuilder.build();
        } catch (ParserException e) {
            throw new ParserException("Could not parse provided data as blob packet", e);
        }
    }

    @Override
    public Stream<AbstractPacket> parsePacketsSoftly(byte[] rawBytes) {
        Stream.Builder<AbstractPacket> packetStreamBuilder = Stream.builder();
        try {
            BlobPacketParser parser = new BlobPacketParser(rawBytes, 0);
            BlobPacket packet = parser.parse();
            decryptPacket(packet);
            packetStreamBuilder.add(packet);
        } catch (ParserException e) {
            LOGGER.warn("Could not parse provided data as blob packet, dropping remaining bytes");
        }
        return packetStreamBuilder.build();
    }
}
