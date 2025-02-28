/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.packet.parser;

import de.rub.nds.sshattacker.core.data.packet.DataPacket;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class DataPacketParser extends AbstractDataPacketParser<DataPacket> {

    private static final Logger LOGGER = LogManager.getLogger();

    public DataPacketParser(byte[] array, int startPosition) {
        super(array, startPosition);
    }

    @Override
    public DataPacket parse() {
        LOGGER.debug("Parsing DataPacket from serialized bytes:");
        DataPacket packet = new DataPacket();
        packet.setLength(parseIntField());
        // Some SFTP servers actually calculate the length sometimes wrong, we could handle this by
        // not relaying on the length field but parse the packet to the end instead
        packet.setPayload(parseByteArrayField(packet.getLength().getValue()));
        return packet;
    }
}
