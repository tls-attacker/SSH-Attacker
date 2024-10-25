/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.connection.parser;

import de.rub.nds.sshattacker.core.constants.DataFormatConstants;
import de.rub.nds.sshattacker.core.protocol.connection.message.ChannelRequestWindowChangeMessage;
import java.io.InputStream;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class ChannelRequestWindowChangeMessageParser
        extends ChannelRequestMessageParser<ChannelRequestWindowChangeMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public ChannelRequestWindowChangeMessageParser(InputStream stream) {
        super(stream);
    }

    @Override
    public void parse(ChannelRequestWindowChangeMessage message) {
        parseProtocolMessageContents(message);
    }

    public void parseWidthColumns(ChannelRequestWindowChangeMessage message) {
        message.setWidthColumns(parseIntField(DataFormatConstants.UINT32_SIZE));
        LOGGER.debug("Terminal width in colums: {}", message.getWidthColumns().getValue());
    }

    public void parseHeightRows(ChannelRequestWindowChangeMessage message) {
        message.setHeightRows(parseIntField(DataFormatConstants.UINT32_SIZE));
        LOGGER.debug("Terminal height in rows: {}", message.getHeightRows().getValue());
    }

    public void parseWidthPixels(ChannelRequestWindowChangeMessage message) {
        message.setWidthPixels(parseIntField(DataFormatConstants.UINT32_SIZE));
        LOGGER.debug("Terminal width in pixels: {}", message.getWidthPixels().getValue());
    }

    public void parseHeightPixels(ChannelRequestWindowChangeMessage message) {
        message.setHeightPixels(parseIntField(DataFormatConstants.UINT32_SIZE));
        LOGGER.debug("Terminal height in pixels: {}", message.getHeightPixels().getValue());
    }

    @Override
    protected void parseMessageSpecificContents(ChannelRequestWindowChangeMessage message) {
        super.parseMessageSpecificContents(message);
        parseWidthColumns(message);
        parseHeightRows(message);
        parseWidthPixels(message);
        parseHeightPixels(message);
    }
}
