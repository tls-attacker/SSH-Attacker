/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2021 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.packet.serializer;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.sshattacker.core.protocol.packet.BlobPacket;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class BlobPacketSerializer extends AbstractPacketSerializer<BlobPacket> {

    private static final Logger LOGGER = LogManager.getLogger();

    private final BlobPacket packet;

    public BlobPacketSerializer(BlobPacket packet) {
        this.packet = packet;
    }

    @Override
    protected void serializeBytes() {
        LOGGER.debug("Serializing BlobPacket");
        appendBytes(packet.getPayload().getValue());
        LOGGER.debug("Payload: " + ArrayConverter.bytesToHexString(packet.getPayload().getValue()));

        packet.setCompletePacketBytes(getAlreadySerialized());
    }
}
