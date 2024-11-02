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
import java.nio.charset.StandardCharsets;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class UserAuthKeyboardInteractiveMessageSerializer
        extends UserAuthRequestMessageSerializer<UserAuthKeyboardInteractiveMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public UserAuthKeyboardInteractiveMessageSerializer(
            UserAuthKeyboardInteractiveMessage message) {
        super(message);
    }

    private void serializeLanguageTag() {
        Integer languageTagLength = message.getLanguageTagLength().getValue();
        LOGGER.debug("Language tag length: {}", languageTagLength);
        appendInt(languageTagLength, DataFormatConstants.STRING_SIZE_LENGTH);
        String languageTag = message.getLanguageTag().getValue();
        LOGGER.debug("Language tag: {}", () -> backslashEscapeString(languageTag));
        appendString(languageTag, StandardCharsets.US_ASCII);
    }

    private void serializeSubMethods() {
        Integer subMethodsLength = message.getSubMethodsLength().getValue();
        LOGGER.debug("Sub methods length: {}", subMethodsLength);
        appendInt(subMethodsLength, DataFormatConstants.STRING_SIZE_LENGTH);
        String subMethods = message.getSubMethods().getValue();
        LOGGER.debug("Sub methods: {}", () -> backslashEscapeString(subMethods));
        appendString(subMethods, StandardCharsets.UTF_8);
    }

    @Override
    protected void serializeMessageSpecificContents() {
        super.serializeMessageSpecificContents();
        serializeLanguageTag();
        serializeSubMethods();
    }
}
