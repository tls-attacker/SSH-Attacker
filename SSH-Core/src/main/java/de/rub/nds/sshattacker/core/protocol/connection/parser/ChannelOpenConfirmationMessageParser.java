/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.connection.parser;

import de.rub.nds.sshattacker.core.constants.DataFormatConstants;
import de.rub.nds.sshattacker.core.protocol.connection.message.ChannelOpenConfirmationMessage;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class ChannelOpenConfirmationMessageParser
        extends ChannelMessageParser<ChannelOpenConfirmationMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public ChannelOpenConfirmationMessageParser(byte[] array) {
        super(array);
    }

    public ChannelOpenConfirmationMessageParser(byte[] array, int startPosition) {
        super(array, startPosition);
    }

    @Override
    public ChannelOpenConfirmationMessage createMessage() {
        return new ChannelOpenConfirmationMessage();
    }

    private void parseSenderChannel() {
        message.setModSenderChannel(parseIntField(DataFormatConstants.UINT32_SIZE));
        LOGGER.debug("Sender channel: " + message.getModSenderChannel().getValue());
    }

    private void parseWindowSize() {
        message.setWindowSize(parseIntField(DataFormatConstants.UINT32_SIZE));
        LOGGER.debug("Initial window size: " + message.getWindowSize().getValue());
    }

    private void parsePacketSize() {
        message.setPacketSize(parseIntField(DataFormatConstants.UINT32_SIZE));
        LOGGER.debug("Maximum packet size: " + message.getPacketSize().getValue());
    }

    @Override
    protected void parseMessageSpecificContents() {
        super.parseMessageSpecificContents();
        parseSenderChannel();
        parseWindowSize();
        parsePacketSize();
    }
}
