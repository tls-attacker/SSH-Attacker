/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.connection.parser;

import de.rub.nds.sshattacker.core.protocol.connection.message.ChannelRequestWindowChangeMessage;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class ChannelRequestWindowChangeMessageParser
        extends ChannelRequestMessageParser<ChannelRequestWindowChangeMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public ChannelRequestWindowChangeMessageParser(byte[] array) {
        super(array);
    }

    public ChannelRequestWindowChangeMessageParser(byte[] array, int startPosition) {
        super(array, startPosition);
    }

    @Override
    public ChannelRequestWindowChangeMessage createMessage() {
        return new ChannelRequestWindowChangeMessage();
    }

    private void parseWidthColumns() {
        int widthColumns = parseIntField();
        message.setWidthColumns(widthColumns);
        LOGGER.debug("Terminal width in colums: {}", widthColumns);
    }

    private void parseHeightRows() {
        int heightRows = parseIntField();
        message.setHeightRows(heightRows);
        LOGGER.debug("Terminal height in rows: {}", heightRows);
    }

    private void parseWidthPixels() {
        int widthPixels = parseIntField();
        message.setWidthPixels(widthPixels);
        LOGGER.debug("Terminal width in pixels: {}", widthPixels);
    }

    private void parseHeightPixels() {
        int heightPixels = parseIntField();
        message.setHeightPixels(heightPixels);
        LOGGER.debug("Terminal height in pixels: {}", heightPixels);
    }

    @Override
    protected void parseMessageSpecificContents() {
        super.parseMessageSpecificContents();
        parseWidthColumns();
        parseHeightRows();
        parseWidthPixels();
        parseHeightPixels();
    }
}
