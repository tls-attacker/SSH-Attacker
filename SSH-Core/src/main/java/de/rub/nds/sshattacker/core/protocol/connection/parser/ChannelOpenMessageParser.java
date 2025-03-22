/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.connection.parser;

import static de.rub.nds.modifiablevariable.util.StringUtil.backslashEscapeString;

import de.rub.nds.sshattacker.core.protocol.common.SshMessageParser;
import de.rub.nds.sshattacker.core.protocol.connection.message.ChannelOpenMessage;
import java.nio.charset.StandardCharsets;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public abstract class ChannelOpenMessageParser<T extends ChannelOpenMessage<T>>
        extends SshMessageParser<T> {

    private static final Logger LOGGER = LogManager.getLogger();

    protected ChannelOpenMessageParser(byte[] array) {
        super(array);
    }

    protected ChannelOpenMessageParser(byte[] array, int startPosition) {
        super(array, startPosition);
    }

    private void parseChannelType() {
        int channelTypeLength = parseIntField();
        message.setChannelTypeLength(channelTypeLength);
        LOGGER.debug("Channel type length: {}", channelTypeLength);
        String channelType = parseByteString(channelTypeLength, StandardCharsets.US_ASCII);
        message.setChannelType(channelType);
        LOGGER.debug("Channel type: {}", () -> backslashEscapeString(channelType));
    }

    private void parseSenderChannel() {
        int senderChannelId = parseIntField();
        message.setSenderChannelId(senderChannelId);
        LOGGER.debug("Sender channel id: {}", senderChannelId);
    }

    private void parseWindowSize() {
        int windowSize = parseIntField();
        message.setWindowSize(windowSize);
        LOGGER.debug("Initial window size: {}", windowSize);
    }

    private void parsePacketSize() {
        int packetSize = parseIntField();
        message.setPacketSize(packetSize);
        LOGGER.debug("Maximum packet size: {}", packetSize);
    }

    @Override
    protected void parseMessageSpecificContents() {
        parseChannelType();
        parseSenderChannel();
        parseWindowSize();
        parsePacketSize();
    }
}
