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

        appendInt(dataPacket.getLength().getValue(), DataFormatConstants.STRING_SIZE_LENGTH);
        LOGGER.debug("Packet length: {}", dataPacket.getLength().getValue());

        appendBytes(dataPacket.getPayload().getValue());
        LOGGER.debug(
                "Payload: {}",
                () -> ArrayConverter.bytesToHexString(dataPacket.getPayload().getValue()));

        dataPacket.setCompletePacketBytes(getAlreadySerialized());
        LOGGER.trace(
                "Complete packet bytes: {}",
                () ->
                        ArrayConverter.bytesToHexString(
                                dataPacket.getCompletePacketBytes().getValue()));
    }
}
