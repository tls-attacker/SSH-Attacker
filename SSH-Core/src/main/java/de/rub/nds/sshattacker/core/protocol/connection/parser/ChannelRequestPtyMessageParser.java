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

    public void parseTermEnvVariable() {
        message.setTermEnvVariableLength(parseIntField(DataFormatConstants.STRING_SIZE_LENGTH));
        LOGGER.debug(
                "TERM environment variable length: "
                        + message.getTermEnvVariableLength().getValue());
        message.setTermEnvVariable(parseByteString(message.getTermEnvVariableLength().getValue()));
        LOGGER.debug("TERM environment variable: " + message.getTermEnvVariable().getValue());
    }

    public void parseWidthCharacters() {
        message.setWidthCharacters(parseIntField(DataFormatConstants.UINT32_SIZE));
        LOGGER.debug("Terminal width in characters: " + message.getWidthCharacters().getValue());
    }

    public void parseHeightRows() {
        message.setHeightRows(parseIntField(DataFormatConstants.UINT32_SIZE));
        LOGGER.debug("Terminal height in rows: " + message.getHeightRows().getValue());
    }

    public void parseWidthPixels() {
        message.setWidthPixels(parseIntField(DataFormatConstants.UINT32_SIZE));
        LOGGER.debug("Terminal width in pixels: " + message.getWidthPixels().getValue());
    }

    public void parseHeightPixels() {
        message.setHeightPixels(parseIntField(DataFormatConstants.UINT32_SIZE));
        LOGGER.debug("Terminal height in pixels: " + message.getHeightPixels().getValue());
    }

    public void parseEncodedTerminalModes() {
        message.setEncodedTerminalModesLength(
                parseIntField(DataFormatConstants.STRING_SIZE_LENGTH));
        LOGGER.debug(
                "Encoded terminal modes length: "
                        + message.getEncodedTerminalModesLength().getValue());
        message.setEncodedTerminalModes(
                parseByteArrayField(message.getEncodedTerminalModesLength().getValue()));
        LOGGER.debug(
                "Encoded terminal modes: "
                        + ArrayConverter.bytesToHexString(
                                message.getEncodedTerminalModes().getValue()));
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
