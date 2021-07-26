/**
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2021 Ruhr University Bochum, Paderborn University,
 * and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.connection.serializer;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.sshattacker.core.constants.DataFormatConstants;
import de.rub.nds.sshattacker.core.protocol.connection.message.ChannelDataMessage;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class ChannelDataMessageSerializer extends ChannelMessageSerializer<ChannelDataMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public ChannelDataMessageSerializer(ChannelDataMessage msg) {
        super(msg);
    }

    private void serializeData() {
        LOGGER.debug("Data length: " + msg.getDataLength().getValue());
        appendInt(msg.getDataLength().getValue(), DataFormatConstants.STRING_SIZE_LENGTH);
        LOGGER.debug("Data: " + ArrayConverter.bytesToRawHexString(msg.getData().getValue()));
        appendBytes(msg.getData().getValue());
    }

    @Override
    protected byte[] serializeMessageSpecificPayload() {
        super.serializeMessageSpecificPayload();
        serializeData();
        return getAlreadySerialized();
    }

}
