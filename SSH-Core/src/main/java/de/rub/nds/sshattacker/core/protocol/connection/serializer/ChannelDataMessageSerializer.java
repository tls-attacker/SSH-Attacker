/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.connection.serializer;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.sshattacker.core.constants.DataFormatConstants;
import de.rub.nds.sshattacker.core.protocol.connection.message.ChannelDataMessage;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class ChannelDataMessageSerializer extends ChannelMessageSerializer<ChannelDataMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public ChannelDataMessageSerializer(ChannelDataMessage message) {
        super(message);
    }

    private void serializeData() {
        Integer dataLength = message.getDataLength().getValue();
        LOGGER.debug("Data length: {}", dataLength);
        appendInt(dataLength, DataFormatConstants.STRING_SIZE_LENGTH);
        byte[] data = message.getData().getValue();
        LOGGER.trace("Data: {}", () -> ArrayConverter.bytesToHexString(data));
        appendBytes(data);
    }

    @Override
    protected void serializeMessageSpecificContents() {
        super.serializeMessageSpecificContents();
        serializeData();
    }
}
