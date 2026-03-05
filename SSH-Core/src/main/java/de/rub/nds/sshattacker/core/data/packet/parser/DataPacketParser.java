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
        // TODO: Some SFTP servers split SFTP messages across multiple ChannelDataMessages.
        //  To handle such SFTP messages we would need a redesign or handle them in a hacky way.
        //  Maybe it would work to handle channel data as an own data stram and create a channel
        //  receive action for it. But hopefully the layer implementations from PR 316 solves the
        //  problem.
        packet.setPayload(parseByteArrayField(packet.getLength().getValue()));
        return packet;
    }
}
