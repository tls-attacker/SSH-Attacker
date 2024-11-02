/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.packet.serializer;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.sshattacker.core.constants.DataFormatConstants;
import de.rub.nds.sshattacker.core.data.packet.DataPacket;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class DataPacketSerializer extends AbstractDataPacketSerializer<DataPacket> {

    private static final Logger LOGGER = LogManager.getLogger();

    private final DataPacket dataPacket;

    public DataPacketSerializer(DataPacket dataPacket) {
        super();
        this.dataPacket = dataPacket;
    }

    @Override
    protected void serializeBytes() {
        LOGGER.debug("Serializing DataPacket to bytes:");

        Integer length = dataPacket.getLength().getValue();
        LOGGER.debug("Packet length: {}", length);
        appendInt(length, DataFormatConstants.STRING_SIZE_LENGTH);

        byte[] payload = dataPacket.getPayload().getValue();
        LOGGER.debug("Payload: {}", () -> ArrayConverter.bytesToHexString(payload));
        appendBytes(payload);

        dataPacket.setCompletePacketBytes(getAlreadySerialized());
        LOGGER.trace(
                "Complete packet bytes: {}",
                () ->
                        ArrayConverter.bytesToHexString(
                                dataPacket.getCompletePacketBytes().getValue()));
    }
}
