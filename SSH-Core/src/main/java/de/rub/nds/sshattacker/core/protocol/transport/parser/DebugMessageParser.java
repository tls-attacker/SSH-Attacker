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
import java.nio.charset.StandardCharsets;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

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
        byte alwaysDisplay = parseByteField(1);
        message.setAlwaysDisplay(alwaysDisplay);
        LOGGER.debug("Always display: {}", Converter.byteToBoolean(alwaysDisplay));
    }

    private void parseMessage() {
        int messageLength = parseIntField(DataFormatConstants.STRING_SIZE_LENGTH);
        message.setMessageLength(messageLength);
        LOGGER.debug("Message length: {}", messageLength);
        String messageStr = parseByteString(messageLength, StandardCharsets.UTF_8);
        message.setMessage(messageStr);
        LOGGER.debug("Message: {}", () -> backslashEscapeString(messageStr));
    }

    private void parseLanguageTag() {
        int languageTagLength = parseIntField(DataFormatConstants.STRING_SIZE_LENGTH);
        message.setLanguageTagLength(languageTagLength);
        LOGGER.debug("Language tag length: {}", languageTagLength);
        String languageTag = parseByteString(languageTagLength, StandardCharsets.US_ASCII);
        message.setLanguageTag(languageTag);
        LOGGER.debug("Language tag: {}", () -> backslashEscapeString(languageTag));
    }

    @Override
    protected void parseMessageSpecificContents() {
        parseAlwaysDisplay();
        parseMessage();
        parseLanguageTag();
    }
}
