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

import de.rub.nds.sshattacker.core.constants.DataFormatConstants;
import de.rub.nds.sshattacker.core.protocol.common.MessageParser;
import de.rub.nds.sshattacker.core.protocol.connection.message.ChannelDataMessage;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class ChannelDataMessageParser extends MessageParser<ChannelDataMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public ChannelDataMessageParser(int startposition, byte[] array) {
        super(startposition, array);
    }

    @Override
    public ChannelDataMessage createMessage() {
        return new ChannelDataMessage();
    }

    @Override
    protected void parseMessageSpecificPayload(ChannelDataMessage msg) {
        msg.setRecipientChannel(parseIntField(DataFormatConstants.INT32_SIZE));
        LOGGER.debug("recipientChannel: " + msg.getRecipientChannel().getValue());
        int length = parseIntField(DataFormatConstants.INT32_SIZE);
        LOGGER.debug("data length: " + length);
        msg.setData(parseByteArrayField(length));
        LOGGER.debug("data: " + new String(msg.getData().getValue()));
    }

}
