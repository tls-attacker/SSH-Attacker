/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.connection.parser;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.sshattacker.core.constants.DataFormatConstants;
import de.rub.nds.sshattacker.core.protocol.connection.message.ChannelRequestPtyMessage;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class ChannelRequestPtyMessageParser
        extends ChannelRequestMessageParser<ChannelRequestPtyMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public ChannelRequestPtyMessageParser(byte[] array) {
        super(array);
    }

    public ChannelRequestPtyMessageParser(byte[] array, int startPosition) {
        super(array, startPosition);
    }

    @Override
    public ChannelRequestPtyMessage createMessage() {
        return new ChannelRequestPtyMessage();
    }

    private void parseTermEnvVariable() {
        int termEnvVariableLength = parseIntField(DataFormatConstants.STRING_SIZE_LENGTH);
        message.setTermEnvVariableLength(termEnvVariableLength);
        LOGGER.debug("TERM environment variable length: {}", termEnvVariableLength);
        String termEnvVariable = parseByteString(termEnvVariableLength);
        message.setTermEnvVariable(termEnvVariable);
        LOGGER.debug("TERM environment variable: {}", termEnvVariable);
    }

    private void parseWidthCharacters() {
        int widthCharacters = parseIntField(DataFormatConstants.UINT32_SIZE);
        message.setWidthCharacters(widthCharacters);
        LOGGER.debug("Terminal width in characters: {}", widthCharacters);
    }

    private void parseHeightRows() {
        int heightRows = parseIntField(DataFormatConstants.UINT32_SIZE);
        message.setHeightRows(heightRows);
        LOGGER.debug("Terminal height in rows: {}", heightRows);
    }

    private void parseWidthPixels() {
        int widthPixels = parseIntField(DataFormatConstants.UINT32_SIZE);
        message.setWidthPixels(widthPixels);
        LOGGER.debug("Terminal width in pixels: {}", widthPixels);
    }

    private void parseHeightPixels() {
        int heightPixels = parseIntField(DataFormatConstants.UINT32_SIZE);
        message.setHeightPixels(heightPixels);
        LOGGER.debug("Terminal height in pixels: {}", heightPixels);
    }

    private void parseEncodedTerminalModes() {
        int encodedTerminalModesLength = parseIntField(DataFormatConstants.STRING_SIZE_LENGTH);
        message.setEncodedTerminalModesLength(encodedTerminalModesLength);
        LOGGER.debug("Encoded terminal modes length: {}", encodedTerminalModesLength);
        byte[] encodedTerminalModes = parseByteArrayField(encodedTerminalModesLength);
        message.setEncodedTerminalModes(encodedTerminalModes);
        LOGGER.debug(
                "Encoded terminal modes: {}",
                () -> ArrayConverter.bytesToHexString(encodedTerminalModes));
    }

    @Override
    protected void parseMessageSpecificContents() {
        super.parseMessageSpecificContents();
        parseTermEnvVariable();
        parseWidthCharacters();
        parseHeightRows();
        parseWidthPixels();
        parseHeightPixels();
        parseEncodedTerminalModes();
    }
}
