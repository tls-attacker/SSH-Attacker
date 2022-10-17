/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.connection.parser;

import de.rub.nds.sshattacker.core.constants.DataFormatConstants;
import de.rub.nds.sshattacker.core.protocol.common.SshMessageParser;
import de.rub.nds.sshattacker.core.protocol.connection.message.ChannelOpenMessage;
import java.nio.charset.StandardCharsets;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class ChannelOpenMessageParser extends SshMessageParser<ChannelOpenMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public ChannelOpenMessageParser(byte[] array) {
        super(array);
    }

    public ChannelOpenMessageParser(byte[] array, int startPosition) {
        super(array, startPosition);
    }

    @Override
    public ChannelOpenMessage createMessage() {
        return new ChannelOpenMessage();
    }

    public void parseChannelType() {
        message.setChannelTypeLength(parseIntField(DataFormatConstants.STRING_SIZE_LENGTH));
        LOGGER.debug("Channel type length: " + message.getChannelTypeLength().getValue());
        message.setChannelType(
                parseByteString(
                        message.getChannelTypeLength().getValue(), StandardCharsets.US_ASCII));
        LOGGER.debug("Channel type: " + message.getChannelType().getValue());
    }

    public void parseSenderChannel() {
        message.setSenderChannelId(parseIntField(DataFormatConstants.UINT32_SIZE));
        LOGGER.debug("Sender channel id: " + message.getSenderChannelId().getValue());
    }

    public void parseWindowSize() {
        message.setWindowSize(parseIntField(DataFormatConstants.UINT32_SIZE));
        LOGGER.debug("Initial window size: " + message.getWindowSize().getValue());
    }

    public void parsePacketSize() {
        message.setPacketSize(parseIntField(DataFormatConstants.UINT32_SIZE));
        LOGGER.debug("Maximum packet size: " + message.getPacketSize().getValue());
    }

    @Override
    protected void parseMessageSpecificContents() {
        parseChannelType();
        parseSenderChannel();
        parseWindowSize();
        parsePacketSize();
    }
}
