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
import de.rub.nds.sshattacker.core.protocol.common.SerializerStream;
import de.rub.nds.sshattacker.core.protocol.common.SshMessageSerializer;
import de.rub.nds.sshattacker.core.protocol.transport.message.DebugMessage;
import de.rub.nds.sshattacker.core.util.Converter;
import java.nio.charset.StandardCharsets;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class DebugMessageSerializer extends SshMessageSerializer<DebugMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    private static void serializeAlwaysDisplayed(DebugMessage object, SerializerStream output) {
        Byte alwaysDisplay = object.getAlwaysDisplay().getValue();
        LOGGER.debug("Always displayed: {}", () -> Converter.byteToBoolean(alwaysDisplay));
        output.appendByte(alwaysDisplay);
    }

    private static void serializeMessage(DebugMessage object, SerializerStream output) {
        Integer messageLength = object.getMessageLength().getValue();
        LOGGER.debug("Message length: {}", messageLength);
        output.appendInt(messageLength, DataFormatConstants.STRING_SIZE_LENGTH);
        String messageStr = object.getMessage().getValue();
        LOGGER.debug("Message: {}", () -> backslashEscapeString(messageStr));
        output.appendString(messageStr, StandardCharsets.UTF_8);
    }

    private static void serializeLanguageTag(DebugMessage object, SerializerStream output) {
        Integer languageTagLength = object.getLanguageTagLength().getValue();
        LOGGER.debug("Language tag length: {}", languageTagLength);
        output.appendInt(languageTagLength, DataFormatConstants.STRING_SIZE_LENGTH);
        String languageTag = object.getLanguageTag().getValue();
        LOGGER.debug("Language tag: {}", () -> backslashEscapeString(languageTag));
        output.appendString(languageTag, StandardCharsets.US_ASCII);
    }

    @Override
    protected void serializeMessageSpecificContents(DebugMessage object, SerializerStream output) {
        serializeAlwaysDisplayed(object, output);
        serializeMessage(object, output);
        serializeLanguageTag(object, output);
    }
}
