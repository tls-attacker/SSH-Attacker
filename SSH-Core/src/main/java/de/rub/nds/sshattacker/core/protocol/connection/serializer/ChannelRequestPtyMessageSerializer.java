/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.connection.serializer;

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

    public void serializeTermEnvVariable() {
        LOGGER.debug(
                "TERM environment variable length: " + message.getTermEnvVariable().getValue());
        appendInt(
                message.getTermEnvVariableLength().getValue(),
                DataFormatConstants.STRING_SIZE_LENGTH);
        LOGGER.debug("TERM environment variable: " + message.getTermEnvVariable().getValue());
        appendString(message.getTermEnvVariable().getValue(), StandardCharsets.UTF_8);
    }

    public void serializeWidthCharacters() {
        LOGGER.debug("Terminal width in characters: " + message.getWidthCharacters().getValue());
        appendInt(message.getWidthCharacters().getValue(), DataFormatConstants.UINT32_SIZE);
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

    public void serializeEncodedTerminalModes() {
        LOGGER.debug(
                "Encoded terminal modes length: " + message.getEncodedTerminalModes().getValue());
        appendInt(
                message.getEncodedTerminalModesLength().getValue(),
                DataFormatConstants.STRING_SIZE_LENGTH);
        LOGGER.debug("Endcoded terminal modes: " + message.getEncodedTerminalModes().getValue());
        appendString(message.getEncodedTerminalModes().getValue(), StandardCharsets.UTF_8);
    }

    @Override
    public void serializeMessageSpecificContents() {
        super.serializeMessageSpecificContents();
        serializeTermEnvVariable();
        serializeWidthCharacters();
        serializeHeightRows();
        serializeWidthPixels();
        serializeHeightPixels();
        serializeEncodedTerminalModes();
    }
}
