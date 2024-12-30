/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.authentication.parser;

import de.rub.nds.sshattacker.core.protocol.authentication.message.UserAuthFailureMessage;
import de.rub.nds.sshattacker.core.protocol.common.SshMessageParser;
import java.nio.charset.StandardCharsets;

public class UserAuthFailureMessageParser extends SshMessageParser<UserAuthFailureMessage> {

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
        message.setPossibleAuthenticationMethodsLength(parseIntField());
        message.setPossibleAuthenticationMethods(
                parseByteString(
                        message.getPossibleAuthenticationMethodsLength().getValue(),
                        StandardCharsets.US_ASCII),
                false);
    }

    private void parsePartialSuccess() {
        message.setPartialSuccess(parseByteField());
    }

    @Override
    protected void parseMessageSpecificContents() {
        parsePossibleAuthenticationMethods();
        parsePartialSuccess();
    }
}
