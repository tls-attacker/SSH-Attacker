/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.packet.parser;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.sshattacker.core.data.packet.PassThroughPacket;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class PassThroughPacketParser extends AbstractDataPacketParser<PassThroughPacket> {

    private static final Logger LOGGER = LogManager.getLogger();

    public PassThroughPacketParser(byte[] array, int startPosition) {
        super(array, startPosition);
    }

    @Override
    public PassThroughPacket parse() {
        LOGGER.trace("Parsing PassThroughPacket from serialized bytes:");
        PassThroughPacket packet = new PassThroughPacket();
        packet.setPayload(parseByteArrayField(getBytesLeft()));
        packet.setCompletePacketBytes(getAlreadyParsed());

        LOGGER.trace(
                "Complete packet bytes: {}",
                ArrayConverter.bytesToHexString(packet.getCompletePacketBytes().getValue()));

        return packet;
    }
}
