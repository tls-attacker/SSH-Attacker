/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.connection.parser;

import de.rub.nds.sshattacker.core.constants.DataFormatConstants;
import de.rub.nds.sshattacker.core.protocol.connection.message.ChannelRequestExitSignalMessage;
import java.nio.charset.StandardCharsets;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class ChannelRequestExitSignalMessageParser
        extends ChannelRequestMessageParser<ChannelRequestExitSignalMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public ChannelRequestExitSignalMessageParser(byte[] array, int startPosition) {
        super(array, startPosition);
    }

    @Override
    protected ChannelRequestExitSignalMessage createMessage() {
        return new ChannelRequestExitSignalMessage();
    }

    public void parseSignalName() {
        message.setSignalNameLength(parseIntField(DataFormatConstants.STRING_SIZE_LENGTH));
        LOGGER.debug("Signal name length: " + message.getSignalNameLength().getValue());
        message.setSignalName(parseByteString(message.getSignalNameLength().getValue()));
        LOGGER.debug("Signal name: " + message.getSignalName().getValue());
    }

    public void parseCoreDump() {
        message.setCoreDump(false);
        LOGGER.debug("Core dumped: " + message.getCoreDump().getValue());
    }

    public void parseErrorMessage() {
        message.setErrorMessageLength(parseIntField(DataFormatConstants.STRING_SIZE_LENGTH));
        LOGGER.debug("Error message " + message.getErrorMessageLength().getValue());
        message.setErrorMessage(parseByteString(message.getErrorMessageLength().getValue()));
        LOGGER.debug("Error message: " + message.getErrorMessage().getValue());
    }

    private void parseLanguageTag() {
        message.setLanguageTagLength(parseIntField(DataFormatConstants.STRING_SIZE_LENGTH));
        LOGGER.debug("Language tag length: " + message.getLanguageTagLength().getValue());
        message.setLanguageTag(
                parseByteString(
                        message.getLanguageTagLength().getValue(), StandardCharsets.US_ASCII),
                false);
        LOGGER.debug("Language tag: " + message.getLanguageTag().getValue());
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
