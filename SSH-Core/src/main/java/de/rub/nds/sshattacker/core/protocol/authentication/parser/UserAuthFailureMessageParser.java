/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.authentication.parser;

import static de.rub.nds.modifiablevariable.util.StringUtil.backslashEscapeString;

import de.rub.nds.sshattacker.core.protocol.authentication.message.UserAuthFailureMessage;
import de.rub.nds.sshattacker.core.protocol.common.SshMessageParser;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class UserAuthFailureMessageParser extends SshMessageParser<UserAuthFailureMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public UserAuthFailureMessageParser(byte[] array) {
        super(array);
    }

    public UserAuthFailureMessageParser(byte[] array, int startPosition) {
        super(array, startPosition);
    }

    @Override
    public UserAuthFailureMessage createMessage() {
        return new UserAuthFailureMessage();
    }

    private void parsePossibleAuthenticationMethods() {
        int possibleAuthenticationMethodsLength = parseIntField();
        message.setPossibleAuthenticationMethodsLength(possibleAuthenticationMethodsLength);
        LOGGER.debug(
                "Possible Authentication Methods length: {}", possibleAuthenticationMethodsLength);
        String possibleAuthenticationMethods = parseByteString(possibleAuthenticationMethodsLength);
        message.setPossibleAuthenticationMethods(possibleAuthenticationMethods);
        LOGGER.debug(
                "Possible Authentication Methods: {}",
                () -> backslashEscapeString(possibleAuthenticationMethods));
    }

    private void parsePartialSuccess() {
        byte partialSuccess = parseByteField();
        message.setPartialSuccess(partialSuccess);
        LOGGER.debug("Partial Success: {}", partialSuccess);
    }

    @Override
    protected void parseMessageSpecificContents() {
        parsePossibleAuthenticationMethods();
        parsePartialSuccess();
    }
}
