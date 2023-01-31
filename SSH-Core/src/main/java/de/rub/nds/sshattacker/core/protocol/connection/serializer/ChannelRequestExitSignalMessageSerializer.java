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
import de.rub.nds.sshattacker.core.util.Converter;
import java.nio.charset.StandardCharsets;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class ChannelRequestExitSignalMessageSerializer
        extends ChannelRequestMessageSerializer<ChannelRequestExitSignalMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public ChannelRequestExitSignalMessageSerializer(ChannelRequestExitSignalMessage message) {
        super(message);
    }

    public void serializeSignalName() {
        LOGGER.debug("Signal name length: " + message.getSignalNameLength().getValue());
        appendInt(message.getSignalNameLength().getValue(), DataFormatConstants.STRING_SIZE_LENGTH);
        LOGGER.debug("Signal name: {}", backslashEscapeString(message.getSignalName().getValue()));
        appendString(message.getSignalName().getValue(), StandardCharsets.UTF_8);
    }

    public void serializeCoreDump() {
        LOGGER.debug("Core dumped:" + message.getCoreDump().getValue());
        appendByte(Converter.booleanToByte(message.getCoreDump().getValue()));
    }

    public void serializeErrorMessage() {
        LOGGER.debug("Error message length: " + message.getErrorMessageLength().getValue());
        appendInt(
                message.getErrorMessageLength().getValue(), DataFormatConstants.STRING_SIZE_LENGTH);
        LOGGER.debug(
                "Error message: {}", backslashEscapeString(message.getErrorMessage().getValue()));
        appendString(message.getErrorMessage().getValue(), StandardCharsets.UTF_8);
    }

    private void serializeLanguageTag() {
        LOGGER.debug("Language tag length: " + message.getLanguageTagLength().getValue());
        appendInt(
                message.getLanguageTagLength().getValue(), DataFormatConstants.STRING_SIZE_LENGTH);
        LOGGER.debug(
                "Language tag: {}", backslashEscapeString(message.getLanguageTag().getValue()));
        appendString(message.getLanguageTag().getValue(), StandardCharsets.US_ASCII);
    }

    @Override
    public void serializeMessageSpecificContents() {
        super.serializeMessageSpecificContents();
        serializeSignalName();
        serializeCoreDump();
        serializeErrorMessage();
        serializeLanguageTag();
    }
}
