/**
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2021 Ruhr University Bochum, Paderborn University,
 * and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.authentication.parser;

import de.rub.nds.sshattacker.core.constants.DataFormatConstants;
import de.rub.nds.sshattacker.core.protocol.authentication.message.UserAuthFailureMessage;
import de.rub.nds.sshattacker.core.protocol.common.MessageParser;

import java.nio.charset.StandardCharsets;

public class UserAuthFailureMessageParser extends MessageParser<UserAuthFailureMessage> {

    public UserAuthFailureMessageParser(int startPosition, byte[] array) {
        super(startPosition, array);
    }

    @Override
    public UserAuthFailureMessage createMessage() {
        return new UserAuthFailureMessage();
    }

    private void parsePossibleAuthenticationMethods(UserAuthFailureMessage msg) {
        msg.setPossibleAuthenticationMethodsLength(parseIntField(DataFormatConstants.STRING_SIZE_LENGTH));
        msg.setPossibleAuthenticationMethods(
                parseByteString(msg.getPossibleAuthenticationMethodsLength().getValue(), StandardCharsets.US_ASCII),
                false);
    }

    private void parsePartialSuccess(UserAuthFailureMessage msg) {
        msg.setPartialSuccess(parseByteField(1));
    }

    @Override
    protected void parseMessageSpecificPayload(UserAuthFailureMessage msg) {
        parsePossibleAuthenticationMethods(msg);
        parsePartialSuccess(msg);
    }

}
