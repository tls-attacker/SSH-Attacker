/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.authentication.parser;

import de.rub.nds.sshattacker.core.constants.DataFormatConstants;
import de.rub.nds.sshattacker.core.protocol.authentication.message.UserAuthFailureMessage;
import de.rub.nds.sshattacker.core.protocol.common.SshMessageParser;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class UserAuthFailureMessageParser extends SshMessageParser<UserAuthFailureMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    /*
        public UserAuthFailureMessageParser(byte[] array) {
            super(array);
        }
        public UserAuthFailureMessageParser(byte[] array, int startPosition) {
            super(array, startPosition);
        }
    */

    public UserAuthFailureMessageParser(InputStream stream) {
        super(stream);
    }

    /*   @Override
        public UserAuthFailureMessage createMessage() {
            return new UserAuthFailureMessage();
        }
    */
    @Override
    public void parse(UserAuthFailureMessage message) {
        LOGGER.debug("Parsing UserAuthBannerMessage");
        parseProtocolMessageContents(message);
        message.setCompleteResultingMessage(getAlreadyParsed());
    }

    private void parsePossibleAuthenticationMethods(UserAuthFailureMessage message) {
        message.setPossibleAuthenticationMethodsLength(
                parseIntField(DataFormatConstants.STRING_SIZE_LENGTH));
        message.setPossibleAuthenticationMethods(
                parseByteString(
                        message.getPossibleAuthenticationMethodsLength().getValue(),
                        StandardCharsets.US_ASCII),
                false);
    }

    private void parsePartialSuccess(UserAuthFailureMessage message) {
        message.setPartialSuccess(parseByteField(1));
    }

    @Override
    protected void parseMessageSpecificContents(UserAuthFailureMessage message) {
        parsePossibleAuthenticationMethods(message);
        parsePartialSuccess(message);
    }
}
