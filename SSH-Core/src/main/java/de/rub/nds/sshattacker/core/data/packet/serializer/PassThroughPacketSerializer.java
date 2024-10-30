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
import de.rub.nds.sshattacker.core.data.packet.PassThroughPacket;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class PassThroughPacketSerializer extends AbstractDataPacketSerializer<DataPacket> {

    private static final Logger LOGGER = LogManager.getLogger();

    private final PassThroughPacket passThroughPacket;

    public PassThroughPacketSerializer(PassThroughPacket passThroughPacket) {
        super();
        this.passThroughPacket = passThroughPacket;
    }

    @Override
    protected void serializeBytes() {
        LOGGER.trace("Serializing PassThroughPacket to bytes:");

        appendBytes(passThroughPacket.getPayload().getValue());
        LOGGER.trace(
                "Payload: {}",
                () -> ArrayConverter.bytesToHexString(passThroughPacket.getPayload().getValue()));

        passThroughPacket.setCompletePacketBytes(getAlreadySerialized());
        LOGGER.trace(
                "Complete packet bytes: {}",
                () ->
                        ArrayConverter.bytesToHexString(
                                passThroughPacket.getCompletePacketBytes().getValue()));
    }
}
