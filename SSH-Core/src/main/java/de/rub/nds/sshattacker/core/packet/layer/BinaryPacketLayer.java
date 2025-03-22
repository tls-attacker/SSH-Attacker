/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.packet.layer;

import de.rub.nds.sshattacker.core.exceptions.DecompressionException;
import de.rub.nds.sshattacker.core.exceptions.DecryptionException;
import de.rub.nds.sshattacker.core.exceptions.ParserException;
import de.rub.nds.sshattacker.core.packet.AbstractPacket;
import de.rub.nds.sshattacker.core.packet.BinaryPacket;
import de.rub.nds.sshattacker.core.packet.BlobPacket;
import de.rub.nds.sshattacker.core.packet.parser.BinaryPacketParser;
import de.rub.nds.sshattacker.core.packet.parser.BlobPacketParser;
import de.rub.nds.sshattacker.core.state.SshContext;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class BinaryPacketLayer extends AbstractPacketLayer {

    private static final Logger LOGGER = LogManager.getLogger();

    public BinaryPacketLayer(SshContext context) {
        super(context);
    }

    @Override
    public PacketLayerParseResult parsePacket(byte[] rawBytes, int startPosition)
            throws ParserException {
        try {
            BinaryPacketParser parser =
                    new BinaryPacketParser(
                            rawBytes,
                            startPosition,
                            getDecryptorCipher(),
                            context.getReadSequenceNumber());
            BinaryPacket packet = parser.parse();
            decryptPacket(packet);
            decompressPacket(packet);
            return new PacketLayerParseResult(packet, parser.getPointer() - startPosition);
        } catch (ParserException | DecryptionException | DecompressionException e) {
            throw new ParserException("Could not parse provided data as binary packet", e);
        }
    }

    @Override
    public PacketLayerParseResult parsePacketSoftly(byte[] rawBytes, int startPosition) {
        try {
            BinaryPacketParser parser =
                    new BinaryPacketParser(
                            rawBytes,
                            startPosition,
                            getDecryptorCipher(),
                            context.getReadSequenceNumber());
            BinaryPacket packet = parser.parse();
            decryptPacket(packet);
            decompressPacket(packet);
            return new PacketLayerParseResult(packet, parser.getPointer() - startPosition, true);
        } catch (ParserException | DecryptionException | DecompressionException e) {
            LOGGER.debug("Could not parse binary packet, parsing as blob");
            LOGGER.trace(e);
            try {
                BlobPacketParser parser = new BlobPacketParser(rawBytes, startPosition);
                BlobPacket packet = parser.parse();
                decryptPacket(packet);
                decompressPacket(packet);
                return new PacketLayerParseResult(
                        packet, parser.getPointer() - startPosition, true);
            } catch (ParserException | DecryptionException | DecompressionException ex) {
                LOGGER.warn(
                        "Could not parse data as blob packet, dropping remaining {} bytes",
                        rawBytes.length - startPosition);
                LOGGER.trace("ParserException", ex);
                return new PacketLayerParseResult(null, rawBytes.length - startPosition, true);
            }
        }
    }

    @Override
    protected void decryptPacket(AbstractPacket packet) throws DecryptionException {
        if (!(packet instanceof BinaryPacket)) {
            LOGGER.warn(
                    "Decrypting received non binary packet: {}", packet.getClass().getSimpleName());
        }
        super.decryptPacket(packet);
    }
}
