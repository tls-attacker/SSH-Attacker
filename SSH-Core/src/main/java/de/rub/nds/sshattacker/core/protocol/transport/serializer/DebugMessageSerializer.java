/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.transport.serializer;

import static de.rub.nds.modifiablevariable.util.StringUtil.backslashEscapeString;

import de.rub.nds.sshattacker.core.constants.DataFormatConstants;
import de.rub.nds.sshattacker.core.protocol.common.SshMessageSerializer;
import de.rub.nds.sshattacker.core.protocol.transport.message.DebugMessage;
import de.rub.nds.sshattacker.core.util.Converter;
import java.nio.charset.StandardCharsets;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class DebugMessageSerializer extends SshMessageSerializer<DebugMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public DebugMessageSerializer(DebugMessage message) {
        super(message);
    }

    private void serializeAlwaysDisplayed() {
        Byte alwaysDisplay = message.getAlwaysDisplay().getValue();
        LOGGER.debug("Always displayed: {}", () -> Converter.byteToBoolean(alwaysDisplay));
        appendByte(alwaysDisplay);
    }

    private void serializeMessage() {
        Integer messageLength = message.getMessageLength().getValue();
        LOGGER.debug("Message length: {}", messageLength);
        appendInt(messageLength, DataFormatConstants.STRING_SIZE_LENGTH);
        String messageStr = message.getMessage().getValue();
        LOGGER.debug("Message: {}", () -> backslashEscapeString(messageStr));
        appendString(messageStr, StandardCharsets.UTF_8);
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
        serializeAlwaysDisplayed();
        serializeMessage();
        serializeLanguageTag();
    }
}
