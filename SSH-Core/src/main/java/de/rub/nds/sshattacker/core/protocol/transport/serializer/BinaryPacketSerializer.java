/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2021 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.transport.serializer;

import de.rub.nds.sshattacker.core.constants.BinaryPacketConstants;
import de.rub.nds.sshattacker.core.protocol.common.Serializer;
import de.rub.nds.sshattacker.core.protocol.transport.message.BinaryPacket;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class BinaryPacketSerializer extends Serializer<BinaryPacket> {

    private static final Logger LOGGER = LogManager.getLogger();

    private final BinaryPacket message;

    public BinaryPacketSerializer(BinaryPacket message) {
        this.message = message;
    }

    private void serializePacketLength() {
        LOGGER.debug("Packet length: " + message.getPacketLength().getValue());
        appendInt(message.getPacketLength().getValue(), BinaryPacketConstants.LENGTH_FIELD_LENGTH);
    }

    private void serializePaddingLength() {
        LOGGER.debug("Padding length: " + message.getPaddingLength().getValue());
        appendByte(message.getPaddingLength().getValue());
    }

    private void serializePayload() {
        LOGGER.debug("Payload: " + message.getPayload());
        appendBytes(message.getPayload().getValue());
    }

    private void serializePadding() {
        LOGGER.debug("Padding: " + message.getPadding());
        appendBytes(message.getPadding().getValue());
    }

    private void serializeMac() {
        if (message.getMac() == null) {
            LOGGER.debug("MAC: [none]");
        } else {
            LOGGER.debug("MAC: " + message.getMac());
            appendBytes(message.getMac().getValue());
        }
    }

    @Override
    public void serializeBytes() {
        serializePacketLength();
        serializePaddingLength();
        serializePayload();
        serializePadding();
        serializeMac();
    }

    public byte[] serializeForEncryption() {
        serializePacketLength();
        serializePaddingLength();
        serializePayload();
        serializePadding();
        return getAlreadySerialized();
    }

    public byte[] serializeForETMEncryption() {
        serializePaddingLength();
        serializePayload();
        serializePadding();
        return getAlreadySerialized();
    }
}
