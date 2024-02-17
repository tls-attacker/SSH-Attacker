/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.packet.serializer;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.sshattacker.core.constants.BinaryPacketConstants;
import de.rub.nds.sshattacker.core.constants.BinaryPacketField;
import de.rub.nds.sshattacker.core.packet.BinaryPacket;
import java.util.Set;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class BinaryPacketSerializer extends AbstractPacketSerializer<BinaryPacket> {

    private static final Logger LOGGER = LogManager.getLogger();

    private final BinaryPacket binaryPacket;

    public BinaryPacketSerializer(BinaryPacket binaryPacket) {
        super();
        this.binaryPacket = binaryPacket;
    }

    @Override
    protected byte[] serializeBytes() {
        LOGGER.debug("Serializing BinaryPacket to bytes:");

        Set<BinaryPacketField> encryptedFields =
                binaryPacket.getComputations().getEncryptedPacketFields();
        if (!encryptedFields.contains(BinaryPacketField.PACKET_LENGTH)) {
            appendInt(
                    binaryPacket.getLength().getValue(), BinaryPacketConstants.LENGTH_FIELD_LENGTH);
            LOGGER.debug("Packet length: {}", binaryPacket.getLength().getValue());
        }
        if (!encryptedFields.contains(BinaryPacketField.PADDING_LENGTH)) {
            appendByte(binaryPacket.getPaddingLength().getValue());
            LOGGER.debug("Padding length: {}", binaryPacket.getPaddingLength().getValue());
        }
        appendBytes(binaryPacket.getCiphertext().getValue());
        LOGGER.debug(
                "Ciphertext: {}",
                ArrayConverter.bytesToHexString(binaryPacket.getCiphertext().getValue()));
        if (!encryptedFields.contains(BinaryPacketField.PADDING)) {
            appendBytes(binaryPacket.getPadding().getValue());
            LOGGER.debug(
                    "Padding: {}",
                    ArrayConverter.bytesToHexString(binaryPacket.getPadding().getValue()));
        }
        appendBytes(binaryPacket.getMac().getValue());
        LOGGER.debug(
                "MAC / Authentication tag: {}",
                ArrayConverter.bytesToHexString(binaryPacket.getMac().getValue()));

        binaryPacket.setCompletePacketBytes(getAlreadySerialized());
        LOGGER.trace(
                "Complete packet bytes: {}",
                ArrayConverter.bytesToHexString(binaryPacket.getCompletePacketBytes().getValue()));
        return getAlreadySerialized();
    }
}
