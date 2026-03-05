/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.connection.parser;

import static de.rub.nds.modifiablevariable.util.StringUtil.backslashEscapeString;

import de.rub.nds.sshattacker.core.protocol.connection.message.ChannelRequestExitSignalMessage;
import java.nio.charset.StandardCharsets;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class ChannelRequestExitSignalMessageParser
        extends ChannelRequestMessageParser<ChannelRequestExitSignalMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public ChannelRequestExitSignalMessageParser(byte[] array) {
        super(array);
    }

    public ChannelRequestExitSignalMessageParser(byte[] array, int startPosition) {
        super(array, startPosition);
    }

    @Override
    public ChannelRequestExitSignalMessage createMessage() {
        return new ChannelRequestExitSignalMessage();
    }

    private void parseSignalName() {
        int signalNameLength = parseIntField();
        message.setSignalNameLength(signalNameLength);
        LOGGER.debug("Signal name length: {}", signalNameLength);
        String signalName = parseByteString(signalNameLength);
        message.setSignalName(signalName);
        LOGGER.debug("Signal name: {}", () -> backslashEscapeString(signalName));
    }

    private void parseCoreDump() {
        byte coreDump = parseByteField();
        message.setCoreDump(coreDump);
        LOGGER.debug("Core dumped: {}", coreDump);
    }

    private void parseErrorMessage() {
        int errorMessageLength = parseIntField();
        message.setErrorMessageLength(errorMessageLength);
        LOGGER.debug("Error message length: {}", errorMessageLength);
        String errorMessage = parseByteString(errorMessageLength);
        message.setErrorMessage(errorMessage);
        LOGGER.debug("Error message: {}", () -> backslashEscapeString(errorMessage));
    }

    private void parseLanguageTag() {
        int languageTagLength = parseIntField();
        message.setLanguageTagLength(languageTagLength);
        LOGGER.debug("Language tag length: {}", languageTagLength);
        String languageTag = parseByteString(languageTagLength, StandardCharsets.US_ASCII);
        message.setLanguageTag(languageTag);
        LOGGER.debug("Language tag: {}", () -> backslashEscapeString(languageTag));
    }

    @Override
    protected void parseMessageSpecificContents() {
        super.parseMessageSpecificContents();
        parseSignalName();
        parseCoreDump();
        parseErrorMessage();
        parseLanguageTag();
    }
}
