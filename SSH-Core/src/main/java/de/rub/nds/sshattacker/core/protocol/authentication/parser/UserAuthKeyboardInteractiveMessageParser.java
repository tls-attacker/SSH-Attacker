/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.authentication.parser;

import de.rub.nds.sshattacker.core.constants.DataFormatConstants;
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
        message.setLanguageTagLength(parseIntField(DataFormatConstants.STRING_SIZE_LENGTH));
        LOGGER.debug("Language tag length: " + message.getLanguageTagLength().getValue());
        message.setLanguageTag(
                parseByteString(
                        message.getLanguageTagLength().getValue(), StandardCharsets.US_ASCII));
        LOGGER.debug("Language tag: " + message.getLanguageTag().getValue());
    }

    private void parseSubMethods() {
        message.setSubMethodsLength(parseIntField(DataFormatConstants.STRING_SIZE_LENGTH));
        LOGGER.debug("Sub methods length: " + message.getSubMethodsLength().getValue());
        message.setSubMethods(
                parseByteString(message.getSubMethodsLength().getValue(), StandardCharsets.UTF_8));
        LOGGER.debug("Sub methods: " + message.getSubMethods().getValue());
    }

    @Override
    protected void parseMessageSpecificContents() {
        super.parseMessageSpecificContents();
        parseLanguageTag();
        parseSubMethods();
    }
}
