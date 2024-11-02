/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.connection.serializer;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.sshattacker.core.constants.DataFormatConstants;
import de.rub.nds.sshattacker.core.protocol.connection.message.ChannelRequestPtyMessage;
import java.nio.charset.StandardCharsets;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class ChannelRequestPtyMessageSerializer
        extends ChannelRequestMessageSerializer<ChannelRequestPtyMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public ChannelRequestPtyMessageSerializer(ChannelRequestPtyMessage message) {
        super(message);
    }

    private void serializeTermEnvVariable() {
        LOGGER.debug(
                "TERM environment variable length: {}", message.getTermEnvVariable().getValue());
        appendInt(
                message.getTermEnvVariableLength().getValue(),
                DataFormatConstants.STRING_SIZE_LENGTH);
        LOGGER.debug("TERM environment variable: {}", message.getTermEnvVariable().getValue());
        appendString(message.getTermEnvVariable().getValue(), StandardCharsets.UTF_8);
    }

    private void serializeWidthCharacters() {
        Integer widthCharacters = message.getWidthCharacters().getValue();
        LOGGER.debug("Terminal width in characters: {}", widthCharacters);
        appendInt(widthCharacters, DataFormatConstants.UINT32_SIZE);
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

    private void serializeEncodedTerminalModes() {
        Integer encodedTerminalModesLength = message.getEncodedTerminalModesLength().getValue();
        LOGGER.debug("Encoded terminal modes length: {}", encodedTerminalModesLength);
        appendInt(encodedTerminalModesLength, DataFormatConstants.STRING_SIZE_LENGTH);
        byte[] encodedTerminalModes = message.getEncodedTerminalModes().getValue();
        LOGGER.debug(
                "Endcoded terminal modes: {}",
                () -> ArrayConverter.bytesToHexString(encodedTerminalModes));
        appendBytes(encodedTerminalModes);
    }

    @Override
    protected void serializeMessageSpecificContents() {
        super.serializeMessageSpecificContents();
        serializeTermEnvVariable();
        serializeWidthCharacters();
        serializeHeightRows();
        serializeWidthPixels();
        serializeHeightPixels();
        serializeEncodedTerminalModes();
    }
}
