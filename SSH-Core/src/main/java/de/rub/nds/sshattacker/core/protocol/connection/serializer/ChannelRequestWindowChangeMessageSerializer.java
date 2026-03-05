/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.connection.serializer;

import de.rub.nds.sshattacker.core.protocol.common.SerializerStream;
import de.rub.nds.sshattacker.core.protocol.connection.message.ChannelRequestWindowChangeMessage;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class ChannelRequestWindowChangeMessageSerializer
        extends ChannelRequestMessageSerializer<ChannelRequestWindowChangeMessage> {
    private static final Logger LOGGER = LogManager.getLogger();

    private static void serializeWidthColums(
            ChannelRequestWindowChangeMessage object, SerializerStream output) {
        Integer widthPixels = object.getWidthPixels().getValue();
        LOGGER.debug("Terminal width in colums: {}", widthPixels);
        output.appendInt(widthPixels);
    }

    private static void serializeHeightRows(
            ChannelRequestWindowChangeMessage object, SerializerStream output) {
        Integer heightRows = object.getHeightRows().getValue();
        LOGGER.debug("Terminal height in rows: {}", heightRows);
        output.appendInt(heightRows);
    }

    private static void serializeWidthPixels(
            ChannelRequestWindowChangeMessage object, SerializerStream output) {
        Integer widthPixels = object.getWidthPixels().getValue();
        LOGGER.debug("Terminal width in pixels: {}", widthPixels);
        output.appendInt(widthPixels);
    }

    private static void serializeHeightPixels(
            ChannelRequestWindowChangeMessage object, SerializerStream output) {
        Integer heightPixels = object.getHeightPixels().getValue();
        LOGGER.debug("Terminal height in pixels: {}", heightPixels);
        output.appendInt(heightPixels);
    }

    @Override
    protected void serializeMessageSpecificContents(
            ChannelRequestWindowChangeMessage object, SerializerStream output) {
        super.serializeMessageSpecificContents(object, output);
        serializeWidthColums(object, output);
        serializeHeightRows(object, output);
        serializeWidthPixels(object, output);
        serializeHeightPixels(object, output);
    }
}
