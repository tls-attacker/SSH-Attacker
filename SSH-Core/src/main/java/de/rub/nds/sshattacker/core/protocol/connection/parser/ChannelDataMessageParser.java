/**
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2021 Ruhr University Bochum, Paderborn University,
 * and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.connection.parser;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.sshattacker.core.constants.DataFormatConstants;
import de.rub.nds.sshattacker.core.protocol.connection.message.ChannelDataMessage;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class ChannelDataMessageParser extends ChannelMessageParser<ChannelDataMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public ChannelDataMessageParser(int startPosition, byte[] array) {
        super(startPosition, array);
    }

    @Override
    public ChannelDataMessage createMessage() {
        return new ChannelDataMessage();
    }

    private void parseData(ChannelDataMessage msg) {
        msg.setDataLength(parseIntField(DataFormatConstants.STRING_SIZE_LENGTH));
        LOGGER.debug("Data length: " + msg.getDataLength().getValue());
        msg.setData(parseByteArrayField(msg.getDataLength().getValue()), false);
        LOGGER.debug("Data: " + ArrayConverter.bytesToRawHexString(msg.getData().getValue()));
    }

    @Override
    protected void parseMessageSpecificPayload(ChannelDataMessage msg) {
        super.parseMessageSpecificPayload(msg);
        parseData(msg);
    }

}
