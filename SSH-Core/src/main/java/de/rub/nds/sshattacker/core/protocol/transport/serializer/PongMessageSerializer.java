/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.transport.serializer;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.sshattacker.core.constants.DataFormatConstants;
import de.rub.nds.sshattacker.core.protocol.common.SshMessageSerializer;
import de.rub.nds.sshattacker.core.protocol.transport.message.PongMessage;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class PongMessageSerializer extends SshMessageSerializer<PongMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public PongMessageSerializer(PongMessage message) {
        super(message);
    }

    @Override
    protected void serializeMessageSpecificContents() {
        Integer dataLength = message.getDataLength().getValue();
        LOGGER.debug("Data length: {}", dataLength);
        appendInt(dataLength, DataFormatConstants.STRING_SIZE_LENGTH);
        byte[] data = message.getData().getValue();
        LOGGER.debug("Data: {}", () -> ArrayConverter.bytesToRawHexString(data));
        appendBytes(data);
    }
}
