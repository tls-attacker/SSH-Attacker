/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.packet.serializer;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.sshattacker.core.data.packet.DataPacket;
import de.rub.nds.sshattacker.core.protocol.common.SerializerStream;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class DataPacketSerializer extends AbstractDataPacketSerializer<DataPacket> {

    private static final Logger LOGGER = LogManager.getLogger();

    @Override
    protected void serializeBytes(DataPacket object, SerializerStream output) {
        LOGGER.debug("Serializing DataPacket to bytes:");

        Integer length = object.getLength().getValue();
        LOGGER.debug("Packet length: {}", length);
        output.appendInt(length);

        byte[] payload = object.getPayload().getValue();
        LOGGER.trace("Payload: {}", () -> ArrayConverter.bytesToHexString(payload));
        output.appendBytes(payload);
    }
}
