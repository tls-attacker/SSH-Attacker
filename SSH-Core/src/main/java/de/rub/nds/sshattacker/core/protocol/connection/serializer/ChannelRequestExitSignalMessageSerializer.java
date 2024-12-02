/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.connection.serializer;

import static de.rub.nds.modifiablevariable.util.StringUtil.backslashEscapeString;

import de.rub.nds.sshattacker.core.constants.DataFormatConstants;
import de.rub.nds.sshattacker.core.protocol.connection.message.ChannelRequestExitSignalMessage;
import java.nio.charset.StandardCharsets;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class ChannelRequestExitSignalMessageSerializer
        extends ChannelRequestMessageSerializer<ChannelRequestExitSignalMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public ChannelRequestExitSignalMessageSerializer(ChannelRequestExitSignalMessage message) {
        super(message);
    }

    private void serializeSignalName() {
        Integer signalNameLength = message.getSignalNameLength().getValue();
        LOGGER.debug("Signal name length: {}", signalNameLength);
        appendInt(signalNameLength, DataFormatConstants.STRING_SIZE_LENGTH);
        String signalName = message.getSignalName().getValue();
        LOGGER.debug("Signal name: {}", () -> backslashEscapeString(signalName));
        appendString(signalName, StandardCharsets.UTF_8);
    }

    private void serializeCoreDump() {
        byte coreDump = message.getCoreDump().getValue();
        LOGGER.debug("Core dumped:{}", coreDump);
        appendByte(coreDump);
    }

    private void serializeErrorMessage() {
        Integer errorMessageLength = message.getErrorMessageLength().getValue();
        LOGGER.debug("Error message length: {}", errorMessageLength);
        appendInt(errorMessageLength, DataFormatConstants.STRING_SIZE_LENGTH);
        String errorMessage = message.getErrorMessage().getValue();
        LOGGER.debug("Error message: {}", () -> backslashEscapeString(errorMessage));
        appendString(errorMessage, StandardCharsets.UTF_8);
    }

    private void serializeLanguageTag() {
        Integer languageTagLength = message.getLanguageTagLength().getValue();
        LOGGER.debug("Language tag length: {}", languageTagLength);
        appendInt(languageTagLength, DataFormatConstants.STRING_SIZE_LENGTH);
        String languageTag = message.getLanguageTag().getValue();
        LOGGER.debug("Language tag: {}", () -> backslashEscapeString(languageTag));
        appendString(languageTag, StandardCharsets.US_ASCII);
    }

    @Override
    protected void serializeMessageSpecificContents() {
        super.serializeMessageSpecificContents();
        serializeSignalName();
        serializeCoreDump();
        serializeErrorMessage();
        serializeLanguageTag();
    }
}
