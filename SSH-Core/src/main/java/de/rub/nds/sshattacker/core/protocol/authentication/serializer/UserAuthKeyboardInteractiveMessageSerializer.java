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
        LOGGER.debug("Language tag length: {}", message.getLanguageTagLength().getValue());
        appendInt(
                message.getLanguageTagLength().getValue(), DataFormatConstants.STRING_SIZE_LENGTH);
        LOGGER.debug(
                "Language tag: {}",
                () -> backslashEscapeString(message.getLanguageTag().getValue()));
        appendString(message.getLanguageTag().getValue(), StandardCharsets.US_ASCII);
    }

    private void serializeSubMethods() {
        LOGGER.debug("Sub methods length: {}", message.getSubMethodsLength().getValue());
        appendInt(message.getSubMethodsLength().getValue(), DataFormatConstants.STRING_SIZE_LENGTH);
        LOGGER.debug(
                "Sub methods: {}", () -> backslashEscapeString(message.getSubMethods().getValue()));
        appendString(message.getSubMethods().getValue(), StandardCharsets.UTF_8);
    }

    @Override
    protected void serializeMessageSpecificContents() {
        super.serializeMessageSpecificContents();
        serializeLanguageTag();
        serializeSubMethods();
    }
}
