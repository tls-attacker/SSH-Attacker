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
import de.rub.nds.sshattacker.core.protocol.connection.message.ChannelOpenMessage;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.nio.charset.StandardCharsets;

public class ChannelOpenMessageParser extends MessageParser<ChannelOpenMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public ChannelOpenMessageParser(int startPosition, byte[] array) {
        super(startPosition, array);
    }

    @Override
    public ChannelOpenMessage createMessage() {
        return new ChannelOpenMessage();
    }

    public void parseChannelType(ChannelOpenMessage msg) {
        msg.setChannelTypeLength(parseIntField(DataFormatConstants.STRING_SIZE_LENGTH));
        LOGGER.debug("Channel type length: " + msg.getChannelTypeLength().getValue());
        msg.setChannelType(parseByteString(msg.getChannelTypeLength().getValue(), StandardCharsets.US_ASCII), false);
        LOGGER.debug("Channel type: " + msg.getChannelType().getValue());
    }

    public void parseSenderChannel(ChannelOpenMessage msg) {
        msg.setSenderChannel(parseIntField(DataFormatConstants.INT32_SIZE));
        LOGGER.debug("Sender channel: " + msg.getSenderChannel().getValue());
    }

    public void parseWindowSize(ChannelOpenMessage msg) {
        msg.setWindowSize(parseIntField(DataFormatConstants.INT32_SIZE));
        LOGGER.debug("Initial window size: " + msg.getWindowSize().getValue());
    }

    public void parsePacketSize(ChannelOpenMessage msg) {
        msg.setPacketSize(parseIntField(DataFormatConstants.INT32_SIZE));
        LOGGER.debug("Maximum packet size: " + msg.getPacketSize().getValue());
    }

    @Override
    protected void parseMessageSpecificPayload(ChannelOpenMessage msg) {
        parseChannelType(msg);
        parseSenderChannel(msg);
        parseWindowSize(msg);
        parsePacketSize(msg);
    }
}
