/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.packet.parser;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.sshattacker.core.packet.BlobPacket;
import java.io.InputStream;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class BlobPacketParser extends AbstractPacketParser<BlobPacket> {

    private static final Logger LOGGER = LogManager.getLogger();

    /*public BlobPacketParser(byte[] array, int startPosition) {
        super(array, startPosition);
    }*/

    public BlobPacketParser(InputStream stream) {
        super(stream);
    }

    @Override
    public void parse(BlobPacket blobPacket) {
        LOGGER.debug("Parsing BlobPacket from serialized bytes:");

        // BlobPacket packet = new BlobPacket();
        blobPacket.setCiphertext(parseByteArrayField(getBytesLeft()));
        blobPacket.setCompletePacketBytes(getAlreadyParsed());

        LOGGER.debug(
                "Complete packet bytes: {}",
                ArrayConverter.bytesToHexString(blobPacket.getCompletePacketBytes().getValue()));

        // return packet;
    }
}
