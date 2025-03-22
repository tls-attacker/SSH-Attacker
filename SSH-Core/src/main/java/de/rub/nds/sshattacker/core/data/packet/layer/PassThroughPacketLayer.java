/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.packet.layer;

import de.rub.nds.sshattacker.core.data.packet.PassThroughPacket;
import de.rub.nds.sshattacker.core.data.packet.parser.PassThroughPacketParser;
import de.rub.nds.sshattacker.core.exceptions.ParserException;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public final class PassThroughPacketLayer extends AbstractDataPacketLayer {

    private static final Logger LOGGER = LogManager.getLogger();

    public static final PassThroughPacketLayer INSTANCE = new PassThroughPacketLayer();

    private PassThroughPacketLayer() {
        super();
    }

    @Override
    public DataPacketLayerParseResult parsePacket(byte[] rawBytes, int startPosition)
            throws ParserException {
        try {
            PassThroughPacketParser parser = new PassThroughPacketParser(rawBytes, startPosition);
            PassThroughPacket packet = parser.parse();
            return new DataPacketLayerParseResult(packet, parser.getPointer() - startPosition);
        } catch (ParserException e) {
            throw new ParserException("Could not parse provided data as pass-through packet", e);
        }
    }

    @Override
    public DataPacketLayerParseResult parsePacketSoftly(byte[] rawBytes, int startPosition) {
        try {
            return parsePacket(rawBytes, startPosition);
        } catch (ParserException ex) {
            LOGGER.warn(
                    "Could not parse provided data as pass-through packet, dropping remaining {} bytes",
                    rawBytes.length - startPosition);
            LOGGER.debug("ParserException", ex);
            return new DataPacketLayerParseResult(null, rawBytes.length - startPosition, true);
        }
    }
}
