/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.connection.parser;

import static de.rub.nds.modifiablevariable.util.StringUtil.backslashEscapeString;

import de.rub.nds.sshattacker.core.constants.DataFormatConstants;
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
        message.setSignalNameLength(parseIntField(DataFormatConstants.STRING_SIZE_LENGTH));
        LOGGER.debug("Signal name length: {}", message.getSignalNameLength().getValue());
        message.setSignalName(parseByteString(message.getSignalNameLength().getValue()));
        LOGGER.debug(
                "Signal name: {}", () -> backslashEscapeString(message.getSignalName().getValue()));
    }

    private void parseCoreDump() {
        message.setCoreDump(false);
        LOGGER.debug("Core dumped: {}", message.getCoreDump().getValue());
    }

    private void parseErrorMessage() {
        message.setErrorMessageLength(parseIntField(DataFormatConstants.STRING_SIZE_LENGTH));
        LOGGER.debug("Error message length: {}", message.getErrorMessageLength().getValue());
        message.setErrorMessage(parseByteString(message.getErrorMessageLength().getValue()));
        LOGGER.debug(
                "Error message: {}",
                () -> backslashEscapeString(message.getErrorMessage().getValue()));
    }

    private void parseLanguageTag() {
        message.setLanguageTagLength(parseIntField(DataFormatConstants.STRING_SIZE_LENGTH));
        LOGGER.debug("Language tag length: {}", message.getLanguageTagLength().getValue());
        message.setLanguageTag(
                parseByteString(
                        message.getLanguageTagLength().getValue(), StandardCharsets.US_ASCII));
        LOGGER.debug(
                "Language tag: {}",
                () -> backslashEscapeString(message.getLanguageTag().getValue()));
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
