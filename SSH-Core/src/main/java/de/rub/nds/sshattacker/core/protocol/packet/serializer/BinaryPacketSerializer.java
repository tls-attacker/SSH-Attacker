/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2021 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.packet.serializer;

import de.rub.nds.sshattacker.core.constants.BinaryPacketConstants;
import de.rub.nds.sshattacker.core.constants.BinaryPacketField;
import de.rub.nds.sshattacker.core.protocol.packet.BinaryPacket;
import de.rub.nds.sshattacker.core.protocol.packet.PacketCryptoComputations;
import java.util.Set;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class BinaryPacketSerializer extends AbstractPacketSerializer<BinaryPacket> {

    private static final Logger LOGGER = LogManager.getLogger();

    private final BinaryPacket binaryPacket;

    public BinaryPacketSerializer(BinaryPacket binaryPacket) {
        this.binaryPacket = binaryPacket;
    }

    @Override
    protected void serializeBytes() {
        LOGGER.debug("Serializing BinaryPacket");

        PacketCryptoComputations computations = binaryPacket.getComputations();
        Set<BinaryPacketField> encryptedFields = computations.getEncryptedPacketFields();
        if (!encryptedFields.contains(BinaryPacketField.PACKET_LENGTH)) {
            appendInt(
                    binaryPacket.getLength().getValue(), BinaryPacketConstants.LENGTH_FIELD_LENGTH);
        }
        if (!encryptedFields.contains(BinaryPacketField.PADDING_LENGTH)) {
            appendByte(computations.getPaddingLength().getValue());
        }
        if (!encryptedFields.contains(BinaryPacketField.PAYLOAD)) {
            appendBytes(binaryPacket.getPayload().getValue());
        }
        if (!encryptedFields.contains(BinaryPacketField.PADDING)) {
            appendBytes(computations.getPadding().getValue());
        }
        appendBytes(computations.getCiphertext().getValue());
        appendBytes(computations.getMac().getValue());

        binaryPacket.setCompletePacketBytes(getAlreadySerialized());
    }
}
