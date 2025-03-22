/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.authentication.parser;

import static de.rub.nds.modifiablevariable.util.StringUtil.backslashEscapeString;

import de.rub.nds.sshattacker.core.protocol.authentication.message.UserAuthBannerMessage;
import de.rub.nds.sshattacker.core.protocol.common.SshMessageParser;
import java.nio.charset.StandardCharsets;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class UserAuthBannerMessageParser extends SshMessageParser<UserAuthBannerMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public UserAuthBannerMessageParser(byte[] array) {
        super(array);
    }

    public UserAuthBannerMessageParser(byte[] array, int startPosition) {
        super(array, startPosition);
    }

    @Override
    public UserAuthBannerMessage createMessage() {
        return new UserAuthBannerMessage();
    }

    private void parseMessage() {
        int messageLength = parseIntField();
        message.setMessageLength(messageLength);
        LOGGER.debug("Message length: {}", messageLength);
        String messageStr = parseByteString(messageLength, StandardCharsets.UTF_8);
        message.setMessage(messageStr);
        LOGGER.debug("Message: {}", () -> backslashEscapeString(messageStr));
    }

    private void parseLanguageTag() {
        int languageTagLength = parseIntField();
        message.setLanguageTagLength(languageTagLength);
        LOGGER.debug("Language Tag length: {}", languageTagLength);
        String languageTag = parseByteString(languageTagLength, StandardCharsets.US_ASCII);
        message.setLanguageTag(languageTag);
        LOGGER.debug("Language Tag: {}", () -> backslashEscapeString(languageTag));
    }

    @Override
    protected void parseMessageSpecificContents() {
        parseMessage();
        parseLanguageTag();
    }
}
