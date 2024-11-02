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
import de.rub.nds.sshattacker.core.protocol.authentication.message.UserAuthBannerMessage;
import de.rub.nds.sshattacker.core.protocol.common.SshMessageSerializer;
import java.nio.charset.StandardCharsets;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class UserAuthBannerMessageSerializer extends SshMessageSerializer<UserAuthBannerMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public UserAuthBannerMessageSerializer(UserAuthBannerMessage message) {
        super(message);
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
        serializeMessage();
        serializeLanguageTag();
    }
}
