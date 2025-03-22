/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.authentication.parser;

import static de.rub.nds.modifiablevariable.util.StringUtil.backslashEscapeString;

import de.rub.nds.sshattacker.core.protocol.authentication.message.UserAuthKeyboardInteractiveMessage;
import java.nio.charset.StandardCharsets;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class UserAuthKeyboardInteractiveMessageParser
        extends UserAuthRequestMessageParser<UserAuthKeyboardInteractiveMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public UserAuthKeyboardInteractiveMessageParser(byte[] array) {
        super(array);
    }

    public UserAuthKeyboardInteractiveMessageParser(byte[] array, int startPosition) {
        super(array, startPosition);
    }

    @Override
    protected UserAuthKeyboardInteractiveMessage createMessage() {
        return new UserAuthKeyboardInteractiveMessage();
    }

    private void parseLanguageTag() {
        int languageTagLength = parseIntField();
        message.setLanguageTagLength(languageTagLength);
        LOGGER.debug("Language tag length: {}", languageTagLength);
        String languageTag = parseByteString(languageTagLength, StandardCharsets.US_ASCII);
        message.setLanguageTag(languageTag);
        LOGGER.debug("Language tag: {}", () -> backslashEscapeString(languageTag));
    }

    private void parseSubMethods() {
        int subMethodsLength = parseIntField();
        message.setSubMethodsLength(subMethodsLength);
        LOGGER.debug("Sub methods length: {}", subMethodsLength);
        String subMethods = parseByteString(subMethodsLength, StandardCharsets.UTF_8);
        message.setSubMethods(subMethods);
        LOGGER.debug("Sub methods: {}", () -> backslashEscapeString(subMethods));
    }

    @Override
    protected void parseMessageSpecificContents() {
        super.parseMessageSpecificContents();
        parseLanguageTag();
        parseSubMethods();
    }
}
