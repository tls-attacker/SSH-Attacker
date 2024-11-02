/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.packet.serializer;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.sshattacker.core.packet.BlobPacket;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class BlobPacketSerializer extends AbstractPacketSerializer<BlobPacket> {

    private static final Logger LOGGER = LogManager.getLogger();

    private final BlobPacket packet;

    public BlobPacketSerializer(BlobPacket packet) {
        super();
        this.packet = packet;
    }

    @Override
    protected void serializeBytes() {
        LOGGER.debug("Serializing BlobPacket");
        byte[] ciphertext = packet.getCiphertext().getValue();
        LOGGER.debug("Ciphertext: {}", () -> ArrayConverter.bytesToHexString(ciphertext));
        appendBytes(ciphertext);

        packet.setCompletePacketBytes(getAlreadySerialized());
    }
}
