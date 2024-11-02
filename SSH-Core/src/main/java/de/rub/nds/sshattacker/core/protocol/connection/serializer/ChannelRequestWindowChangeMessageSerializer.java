/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.connection.serializer;

import de.rub.nds.sshattacker.core.constants.DataFormatConstants;
import de.rub.nds.sshattacker.core.protocol.connection.message.ChannelRequestWindowChangeMessage;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class ChannelRequestWindowChangeMessageSerializer
        extends ChannelRequestMessageSerializer<ChannelRequestWindowChangeMessage> {
    private static final Logger LOGGER = LogManager.getLogger();

    public ChannelRequestWindowChangeMessageSerializer(ChannelRequestWindowChangeMessage message) {
        super(message);
    }

    private void serializeWidthColums() {
        Integer widthPixels = message.getWidthPixels().getValue();
        LOGGER.debug("Terminal width in colums: {}", widthPixels);
        appendInt(widthPixels, DataFormatConstants.UINT32_SIZE);
    }

    private void serializeHeightRows() {
        Integer heightRows = message.getHeightRows().getValue();
        LOGGER.debug("Terminal height in rows: {}", heightRows);
        appendInt(heightRows, DataFormatConstants.UINT32_SIZE);
    }

    private void serializeWidthPixels() {
        Integer widthPixels = message.getWidthPixels().getValue();
        LOGGER.debug("Terminal width in pixels: {}", widthPixels);
        appendInt(widthPixels, DataFormatConstants.UINT32_SIZE);
    }

    private void serializeHeightPixels() {
        Integer heightPixels = message.getHeightPixels().getValue();
        LOGGER.debug("Terminal height in pixels: {}", heightPixels);
        appendInt(heightPixels, DataFormatConstants.UINT32_SIZE);
    }

    @Override
    protected void serializeMessageSpecificContents() {
        super.serializeMessageSpecificContents();
        serializeWidthColums();
        serializeHeightRows();
        serializeWidthPixels();
        serializeHeightPixels();
    }
}
