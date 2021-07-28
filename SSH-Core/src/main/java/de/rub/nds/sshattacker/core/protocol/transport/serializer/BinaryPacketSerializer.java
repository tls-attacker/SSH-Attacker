/**
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2021 Ruhr University Bochum, Paderborn University,
 * and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.transport.serializer;

import de.rub.nds.sshattacker.core.constants.BinaryPacketConstants;
import de.rub.nds.sshattacker.core.protocol.common.Serializer;
import de.rub.nds.sshattacker.core.protocol.transport.message.BinaryPacket;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class BinaryPacketSerializer extends Serializer<BinaryPacket> {

    private static final Logger LOGGER = LogManager.getLogger();

    private final BinaryPacket msg;

    public BinaryPacketSerializer(BinaryPacket msg) {
        this.msg = msg;
    }

    private void serializePacketLength() {
        LOGGER.debug("Packet length: " + msg.getPacketLength().getValue());
        appendInt(msg.getPacketLength().getValue(), BinaryPacketConstants.LENGTH_FIELD_LENGTH);
    }

    private void serializePaddingLength() {
        LOGGER.debug("Padding length: " + msg.getPaddingLength().getValue());
        appendByte(msg.getPaddingLength().getValue());
    }

    private void serializePayload() {
        LOGGER.debug("Payload: " + msg.getPayload());
        appendBytes(msg.getPayload().getValue());
    }

    private void serializePadding() {
        LOGGER.debug("Padding: " + msg.getPadding());
        appendBytes(msg.getPadding().getValue());
    }

    private void serializeMac() {
        if (msg.getMac() == null) {
            LOGGER.debug("MAC: [none]");
        } else {
            LOGGER.debug("MAC: " + msg.getMac());
            appendBytes(msg.getMac().getValue());
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
