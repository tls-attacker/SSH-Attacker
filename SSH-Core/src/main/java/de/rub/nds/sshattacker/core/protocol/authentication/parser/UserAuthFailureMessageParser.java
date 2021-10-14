/**
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * <p>Copyright 2014-2021 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * <p>Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.authentication.parser;

import de.rub.nds.sshattacker.core.constants.DataFormatConstants;
import de.rub.nds.sshattacker.core.protocol.authentication.message.UserAuthFailureMessage;
import de.rub.nds.sshattacker.core.protocol.common.SshMessageParser;
import java.nio.charset.StandardCharsets;

public class UserAuthFailureMessageParser extends SshMessageParser<UserAuthFailureMessage> {

    public UserAuthFailureMessageParser(byte[] array, int startPosition) {
        super(array, startPosition);
    }

    @Override
    public UserAuthFailureMessage createMessage() {
        return new UserAuthFailureMessage();
    }

    private void parsePossibleAuthenticationMethods() {
        message.setPossibleAuthenticationMethodsLength(
                parseIntField(DataFormatConstants.STRING_SIZE_LENGTH));
        message.setPossibleAuthenticationMethods(
                parseByteString(
                        message.getPossibleAuthenticationMethodsLength().getValue(),
                        StandardCharsets.US_ASCII),
                false);
    }

    private void parsePartialSuccess() {
        message.setPartialSuccess(parseByteField(1));
    }

    @Override
    protected void parseMessageSpecificContents() {
        parsePossibleAuthenticationMethods();
        parsePartialSuccess();
    }
}
