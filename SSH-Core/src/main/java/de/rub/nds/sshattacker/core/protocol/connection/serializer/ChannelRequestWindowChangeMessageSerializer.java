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

    public void serializeWidthColums() {
        LOGGER.debug("Terminal width in colums: " + message.getWidthPixels().getValue());
        appendInt(message.getWidthPixels().getValue(), DataFormatConstants.UINT32_SIZE);
    }

    public void serializeHeightRows() {
        LOGGER.debug("Terminal height in rows: " + message.getHeightRows().getValue());
        appendInt(message.getHeightRows().getValue(), DataFormatConstants.UINT32_SIZE);
    }

    public void serializeWidthPixels() {
        LOGGER.debug("Terminal width in pixels: " + message.getWidthPixels().getValue());
        appendInt(message.getWidthPixels().getValue(), DataFormatConstants.UINT32_SIZE);
    }

    public void serializeHeightPixels() {
        LOGGER.debug("Terminal height in pixels: " + message.getHeightPixels().getValue());
        appendInt(message.getHeightPixels().getValue(), DataFormatConstants.UINT32_SIZE);
    }

    @Override
    public void serializeMessageSpecificContents() {
        super.serializeMessageSpecificContents();
        serializeWidthColums();
        serializeHeightRows();
        serializeWidthPixels();
        serializeHeightPixels();
    }
}
