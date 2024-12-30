/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.connection.serializer;

import static de.rub.nds.modifiablevariable.util.StringUtil.backslashEscapeString;

import de.rub.nds.sshattacker.core.protocol.common.SerializerStream;
import de.rub.nds.sshattacker.core.protocol.connection.message.ChannelRequestExitSignalMessage;
import java.nio.charset.StandardCharsets;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class ChannelRequestExitSignalMessageSerializer
        extends ChannelRequestMessageSerializer<ChannelRequestExitSignalMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    private static void serializeSignalName(
            ChannelRequestExitSignalMessage object, SerializerStream output) {
        Integer signalNameLength = object.getSignalNameLength().getValue();
        LOGGER.debug("Signal name length: {}", signalNameLength);
        output.appendInt(signalNameLength);
        String signalName = object.getSignalName().getValue();
        LOGGER.debug("Signal name: {}", () -> backslashEscapeString(signalName));
        output.appendString(signalName, StandardCharsets.UTF_8);
    }

    private static void serializeCoreDump(
            ChannelRequestExitSignalMessage object, SerializerStream output) {
        byte coreDump = object.getCoreDump().getValue();
        LOGGER.debug("Core dumped:{}", coreDump);
        output.appendByte(coreDump);
    }

    private static void serializeErrorMessage(
            ChannelRequestExitSignalMessage object, SerializerStream output) {
        Integer errorMessageLength = object.getErrorMessageLength().getValue();
        LOGGER.debug("Error message length: {}", errorMessageLength);
        output.appendInt(errorMessageLength);
        String errorMessage = object.getErrorMessage().getValue();
        LOGGER.debug("Error message: {}", () -> backslashEscapeString(errorMessage));
        output.appendString(errorMessage, StandardCharsets.UTF_8);
    }

    private static void serializeLanguageTag(
            ChannelRequestExitSignalMessage object, SerializerStream output) {
        Integer languageTagLength = object.getLanguageTagLength().getValue();
        LOGGER.debug("Language tag length: {}", languageTagLength);
        output.appendInt(languageTagLength);
        String languageTag = object.getLanguageTag().getValue();
        LOGGER.debug("Language tag: {}", () -> backslashEscapeString(languageTag));
        output.appendString(languageTag, StandardCharsets.US_ASCII);
    }

    @Override
    protected void serializeMessageSpecificContents(
            ChannelRequestExitSignalMessage object, SerializerStream output) {
        super.serializeMessageSpecificContents(object, output);
        serializeSignalName(object, output);
        serializeCoreDump(object, output);
        serializeErrorMessage(object, output);
        serializeLanguageTag(object, output);
    }
}
