/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.packet.serializer;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.sshattacker.core.data.packet.PassThroughPacket;
import de.rub.nds.sshattacker.core.protocol.common.SerializerStream;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class PassThroughPacketSerializer extends AbstractDataPacketSerializer<PassThroughPacket> {

    private static final Logger LOGGER = LogManager.getLogger();

    @Override
    protected void serializeBytes(PassThroughPacket object, SerializerStream output) {
        LOGGER.trace("Serializing PassThroughPacket to bytes:");

        output.appendBytes(object.getPayload().getValue());
        LOGGER.trace(
                "Payload: {}",
                () -> ArrayConverter.bytesToHexString(object.getPayload().getValue()));
    }
}
