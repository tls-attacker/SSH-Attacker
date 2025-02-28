/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.packet.layer;

import de.rub.nds.sshattacker.core.data.packet.DataPacket;
import de.rub.nds.sshattacker.core.data.packet.parser.DataPacketParser;
import de.rub.nds.sshattacker.core.exceptions.ParserException;
import de.rub.nds.sshattacker.core.state.SshContext;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class DataPacketLayer extends AbstractDataPacketLayer {

    private static final Logger LOGGER = LogManager.getLogger();

    public DataPacketLayer(SshContext context) {
        super(context);
    }

    @Override
    public DataPacketLayerParseResult parsePacket(byte[] rawBytes, int startPosition)
            throws ParserException {
        try {
            DataPacketParser parser = new DataPacketParser(rawBytes, startPosition);
            DataPacket packet = parser.parse();
            return new DataPacketLayerParseResult(packet, parser.getPointer() - startPosition);
        } catch (ParserException e) {
            throw new ParserException("Could not parse provided data as data packet", e);
        }
    }

    @Override
    public DataPacketLayerParseResult parsePacketSoftly(byte[] rawBytes, int startPosition) {
        try {
            return parsePacket(rawBytes, startPosition);
        } catch (ParserException ex) {
            LOGGER.warn(
                    "Could not parse provided data as data packet, dropping remaining {} bytes",
                    rawBytes.length - startPosition);
            LOGGER.debug("ParserException", ex);
            return new DataPacketLayerParseResult(null, rawBytes.length - startPosition, true);
        }
    }
}
