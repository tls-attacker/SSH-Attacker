/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.connection.serializer;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.sshattacker.core.protocol.common.SerializerStream;
import de.rub.nds.sshattacker.core.protocol.connection.message.ChannelRequestPtyMessage;
import java.nio.charset.StandardCharsets;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class ChannelRequestPtyMessageSerializer
        extends ChannelRequestMessageSerializer<ChannelRequestPtyMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    private static void serializeTermEnvVariable(
            ChannelRequestPtyMessage object, SerializerStream output) {
        LOGGER.debug(
                "TERM environment variable length: {}", object.getTermEnvVariable().getValue());
        output.appendInt(object.getTermEnvVariableLength().getValue());
        LOGGER.debug("TERM environment variable: {}", object.getTermEnvVariable().getValue());
        output.appendString(object.getTermEnvVariable().getValue(), StandardCharsets.UTF_8);
    }

    private static void serializeWidthCharacters(
            ChannelRequestPtyMessage object, SerializerStream output) {
        Integer widthCharacters = object.getWidthCharacters().getValue();
        LOGGER.debug("Terminal width in characters: {}", widthCharacters);
        output.appendInt(widthCharacters);
    }

    private static void serializeHeightRows(
            ChannelRequestPtyMessage object, SerializerStream output) {
        Integer heightRows = object.getHeightRows().getValue();
        LOGGER.debug("Terminal height in rows: {}", heightRows);
        output.appendInt(heightRows);
    }

    private static void serializeWidthPixels(
            ChannelRequestPtyMessage object, SerializerStream output) {
        Integer widthPixels = object.getWidthPixels().getValue();
        LOGGER.debug("Terminal width in pixels: {}", widthPixels);
        output.appendInt(widthPixels);
    }

    private static void serializeHeightPixels(
            ChannelRequestPtyMessage object, SerializerStream output) {
        Integer heightPixels = object.getHeightPixels().getValue();
        LOGGER.debug("Terminal height in pixels: {}", heightPixels);
        output.appendInt(heightPixels);
    }

    private static void serializeEncodedTerminalModes(
            ChannelRequestPtyMessage object, SerializerStream output) {
        Integer encodedTerminalModesLength = object.getEncodedTerminalModesLength().getValue();
        LOGGER.debug("Encoded terminal modes length: {}", encodedTerminalModesLength);
        output.appendInt(encodedTerminalModesLength);
        byte[] encodedTerminalModes = object.getEncodedTerminalModes().getValue();
        LOGGER.debug(
                "Endcoded terminal modes: {}",
                () -> ArrayConverter.bytesToHexString(encodedTerminalModes));
        output.appendBytes(encodedTerminalModes);
    }

    @Override
    protected void serializeMessageSpecificContents(
            ChannelRequestPtyMessage object, SerializerStream output) {
        super.serializeMessageSpecificContents(object, output);
        serializeTermEnvVariable(object, output);
        serializeWidthCharacters(object, output);
        serializeHeightRows(object, output);
        serializeWidthPixels(object, output);
        serializeHeightPixels(object, output);
        serializeEncodedTerminalModes(object, output);
    }
}
