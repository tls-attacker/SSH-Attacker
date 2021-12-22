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
import de.rub.nds.sshattacker.core.packet.BinaryPacket;
import de.rub.nds.sshattacker.core.packet.BlobPacket;
import de.rub.nds.sshattacker.core.packet.parser.BinaryPacketParser;
import de.rub.nds.sshattacker.core.packet.parser.BlobPacketParser;
import de.rub.nds.sshattacker.core.state.SshContext;
import java.util.stream.Stream;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class BinaryPacketLayer extends AbstractPacketLayer {

    private static final Logger LOGGER = LogManager.getLogger();

    public BinaryPacketLayer(SshContext context) {
        super(context);
    }

    @Override
    public Stream<AbstractPacket> parsePackets(byte[] rawBytes) throws ParserException {
        Stream.Builder<AbstractPacket> packetStreamBuilder = Stream.builder();
        int dataPointer = 0;
        while (dataPointer != rawBytes.length) {
            try {
                BinaryPacketParser parser =
                        new BinaryPacketParser(
                                rawBytes,
                                dataPointer,
                                getDecryptorCipher(),
                                context.getReadSequenceNumber());
                BinaryPacket packet = parser.parse();
                decryptPacket(packet);
                decompressPacket(packet);
                packetStreamBuilder.add(packet);
                dataPointer = parser.getPointer();
            } catch (ParserException e) {
                throw new ParserException("Could not parse provided data as binary packet", e);
            }
        }

        return packetStreamBuilder.build();
    }

    @Override
    public Stream<AbstractPacket> parsePacketsSoftly(byte[] rawBytes) {
        Stream.Builder<AbstractPacket> packetStreamBuilder = Stream.builder();
        int dataPointer = 0;
        while (dataPointer != rawBytes.length) {
            try {
                BinaryPacketParser parser =
                        new BinaryPacketParser(
                                rawBytes,
                                dataPointer,
                                getDecryptorCipher(),
                                context.getReadSequenceNumber());
                BinaryPacket packet = parser.parse();
                decryptPacket(packet);
                decompressPacket(packet);
                packetStreamBuilder.add(packet);
                dataPointer = parser.getPointer();
            } catch (ParserException e) {
                LOGGER.debug("Could not parse binary packet, parsing as blob");
                LOGGER.trace(e);
                try {
                    BlobPacketParser parser = new BlobPacketParser(rawBytes, dataPointer);
                    BlobPacket packet = parser.parse();
                    decryptPacket(packet);
                    decompressPacket(packet);
                    packetStreamBuilder.add(packet);
                    dataPointer = parser.getPointer();
                } catch (ParserException ex) {
                    LOGGER.warn("Could not parse data as blob packet, dropping remaining bytes");
                    LOGGER.trace(ex);
                    break;
                }
            }
        }

        return packetStreamBuilder.build();
    }

    @Override
    protected void decryptPacket(AbstractPacket packet) {
        if (!(packet instanceof BinaryPacket)) {
            LOGGER.warn("Decrypting received non binary packet: {}", packet);
        }
        super.decryptPacket(packet);
    }
}
