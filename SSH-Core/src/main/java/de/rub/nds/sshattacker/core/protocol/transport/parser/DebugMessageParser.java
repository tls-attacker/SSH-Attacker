/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.transport.parser;

import static de.rub.nds.modifiablevariable.util.StringUtil.backslashEscapeString;

import de.rub.nds.sshattacker.core.constants.DataFormatConstants;
import de.rub.nds.sshattacker.core.protocol.common.SshMessageParser;
import de.rub.nds.sshattacker.core.protocol.transport.message.DebugMessage;
import de.rub.nds.sshattacker.core.util.Converter;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.nio.charset.StandardCharsets;

public class DebugMessageParser extends SshMessageParser<DebugMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public DebugMessageParser(byte[] array) {
        super(array);
    }

    public DebugMessageParser(byte[] array, int startPosition) {
        super(array, startPosition);
    }

    @Override
    public DebugMessage createMessage() {
        return new DebugMessage();
    }

    private void parseAlwaysDisplay() {
        message.setAlwaysDisplay(parseByteField(1));
        LOGGER.debug(
                "Always display: "
                        + Converter.byteToBoolean(message.getAlwaysDisplay().getValue()));
    }

    private void parseMessage() {
        message.setMessageLength(parseIntField(DataFormatConstants.STRING_SIZE_LENGTH));
        LOGGER.debug("Message length: " + message.getMessageLength().getValue());
        message.setMessage(
                parseByteString(message.getMessageLength().getValue(), StandardCharsets.UTF_8));
        LOGGER.debug("Message: " + backslashEscapeString(message.getMessage().getValue()));
    }

    private void parseLanguageTag() {
        message.setLanguageTagLength(parseIntField(DataFormatConstants.STRING_SIZE_LENGTH));
        LOGGER.debug("Language tag length: " + message.getLanguageTagLength().getValue());
        message.setLanguageTag(
                parseByteString(
                        message.getLanguageTagLength().getValue(), StandardCharsets.US_ASCII));
        LOGGER.debug("Language tag: " + backslashEscapeString(message.getLanguageTag().getValue()));
    }

    @Override
    protected void parseMessageSpecificContents() {
        parseAlwaysDisplay();
        parseMessage();
        parseLanguageTag();
    }
}
