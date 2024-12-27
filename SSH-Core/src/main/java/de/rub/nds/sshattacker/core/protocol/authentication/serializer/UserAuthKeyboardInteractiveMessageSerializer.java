/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.authentication.serializer;

import static de.rub.nds.modifiablevariable.util.StringUtil.backslashEscapeString;

import de.rub.nds.sshattacker.core.constants.DataFormatConstants;
import de.rub.nds.sshattacker.core.protocol.authentication.message.UserAuthKeyboardInteractiveMessage;
import de.rub.nds.sshattacker.core.protocol.common.SerializerStream;
import java.nio.charset.StandardCharsets;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class UserAuthKeyboardInteractiveMessageSerializer
        extends UserAuthRequestMessageSerializer<UserAuthKeyboardInteractiveMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    private static void serializeLanguageTag(
            UserAuthKeyboardInteractiveMessage object, SerializerStream output) {
        Integer languageTagLength = object.getLanguageTagLength().getValue();
        LOGGER.debug("Language tag length: {}", languageTagLength);
        output.appendInt(languageTagLength, DataFormatConstants.STRING_SIZE_LENGTH);
        String languageTag = object.getLanguageTag().getValue();
        LOGGER.debug("Language tag: {}", () -> backslashEscapeString(languageTag));
        output.appendString(languageTag, StandardCharsets.US_ASCII);
    }

    private static void serializeSubMethods(
            UserAuthKeyboardInteractiveMessage object, SerializerStream output) {
        Integer subMethodsLength = object.getSubMethodsLength().getValue();
        LOGGER.debug("Sub methods length: {}", subMethodsLength);
        output.appendInt(subMethodsLength, DataFormatConstants.STRING_SIZE_LENGTH);
        String subMethods = object.getSubMethods().getValue();
        LOGGER.debug("Sub methods: {}", () -> backslashEscapeString(subMethods));
        output.appendString(subMethods, StandardCharsets.UTF_8);
    }

    @Override
    protected void serializeMessageSpecificContents(
            UserAuthKeyboardInteractiveMessage object, SerializerStream output) {
        super.serializeMessageSpecificContents(object, output);
        serializeLanguageTag(object, output);
        serializeSubMethods(object, output);
    }
}
