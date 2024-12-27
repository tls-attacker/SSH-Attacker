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
import de.rub.nds.sshattacker.core.protocol.common.SerializerStream;
import java.util.Set;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class BinaryPacketSerializer extends AbstractPacketSerializer<BinaryPacket> {

    private static final Logger LOGGER = LogManager.getLogger();

    @Override
    protected void serializeBytes(BinaryPacket object, SerializerStream output) {
        LOGGER.debug("Serializing BinaryPacket to bytes:");

        Set<BinaryPacketField> encryptedFields =
                object.getComputations().getEncryptedPacketFields();
        if (!encryptedFields.contains(BinaryPacketField.PACKET_LENGTH)) {
            Integer length = object.getLength().getValue();
            LOGGER.debug("Packet length: {}", length);
            output.appendInt(length, BinaryPacketConstants.LENGTH_FIELD_LENGTH);
        }
        if (!encryptedFields.contains(BinaryPacketField.PADDING_LENGTH)) {
            Byte paddingLength = object.getPaddingLength().getValue();
            LOGGER.debug("Padding length: {}", paddingLength);
            output.appendByte(paddingLength);
        }
        byte[] ciphertext = object.getCiphertext().getValue();
        LOGGER.trace(
                "Complete payload bytes: {}",
                () -> ArrayConverter.bytesToHexString(object.getPayload().getValue()));
        LOGGER.debug("Ciphertext: {}", () -> ArrayConverter.bytesToHexString(ciphertext));
        output.appendBytes(ciphertext);
        if (!encryptedFields.contains(BinaryPacketField.PADDING)) {
            byte[] padding = object.getPadding().getValue();
            LOGGER.debug("Padding: {}", () -> ArrayConverter.bytesToHexString(padding));
            output.appendBytes(padding);
        }
        byte[] mac = object.getMac().getValue();
        LOGGER.debug("MAC / Authentication tag: {}", () -> ArrayConverter.bytesToHexString(mac));
        output.appendBytes(mac);
    }
}
