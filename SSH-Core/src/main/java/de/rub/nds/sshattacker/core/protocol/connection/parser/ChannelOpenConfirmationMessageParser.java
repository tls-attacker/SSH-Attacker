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
        int senderChannelId = parseIntField(DataFormatConstants.UINT32_SIZE);
        message.setSenderChannelId(senderChannelId);
        LOGGER.debug("Sender channel id: {}", senderChannelId);
    }

    private void parseWindowSize() {
        int windowSize = parseIntField(DataFormatConstants.UINT32_SIZE);
        message.setWindowSize(windowSize);
        LOGGER.debug("Initial window size: {}", windowSize);
    }

    private void parsePacketSize() {
        int packetSize = parseIntField(DataFormatConstants.UINT32_SIZE);
        message.setPacketSize(packetSize);
        LOGGER.debug("Maximum packet size: {}", packetSize);
    }

    @Override
    protected void parseMessageSpecificContents() {
        super.parseMessageSpecificContents();
        parseSenderChannel();
        parseWindowSize();
        parsePacketSize();
    }
}
