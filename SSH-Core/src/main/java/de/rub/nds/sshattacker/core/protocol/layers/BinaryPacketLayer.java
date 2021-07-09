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
import de.rub.nds.sshattacker.core.protocol.parser.BinaryPacketParser;
import de.rub.nds.sshattacker.core.protocol.serializer.BinaryPacketSerializer;
import de.rub.nds.sshattacker.core.state.SshContext;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.List;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class BinaryPacketLayer {

    private SshContext context;

    private static final Logger LOGGER = LogManager.getLogger();

    public BinaryPacketLayer(SshContext context) {
        this.context = context;
    }

    public List<BinaryPacket> parseBinaryPackets(byte[] raw) {
        return new BinaryPacketParser(0, raw, context).parseAll();
    }

    public byte[] serializeBinaryPacket(BinaryPacket packet) {
        ByteArrayOutputStream serialized = new ByteArrayOutputStream();
        try {
            serialized.write(new BinaryPacketSerializer(packet).serialize());
        } catch (IOException e) {
            LOGGER.debug("Error while writing to ByteArrayOutputStream " + e.getMessage());
        }
        return serialized.toByteArray();
    }

    public byte[] serializeBinaryPackets(List<BinaryPacket> list) {
        ByteArrayOutputStream serialized = new ByteArrayOutputStream();

        for (BinaryPacket packet : list) {
            try {
                serialized.write(serializeBinaryPacket(packet));
            } catch (IOException e) {
                LOGGER.debug("Error while writing to ByteArrayOutputStream " + e.getMessage());
            }
        }
        return serialized.toByteArray();
    }
}
