/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.authentication.parser;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.sshattacker.core.protocol.authentication.message.UserAuthUnknownMessage;
import java.io.InputStream;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class UserAuthUnknownMessageParser
        extends UserAuthRequestMessageParser<UserAuthUnknownMessage> {

    private static final Logger LOGGER = LogManager.getLogger();
    /*

        public UserAuthUnknownMessageParser(byte[] array) {
            super(array);
        }
        public UserAuthUnknownMessageParser(byte[] array, int startPosition) {
            super(array, startPosition);
        }
    */

    public UserAuthUnknownMessageParser(InputStream stream) {
        super(stream);
    }

    /*
        @Override
        public UserAuthUnknownMessage createMessage() {
            return new UserAuthUnknownMessage();
        }
    */

    private void parseMethodSpecificFields(UserAuthUnknownMessage message) {
        message.setMethodSpecificFields(parseByteArrayField(getBytesLeft()));
        LOGGER.debug(
                "Method Specific Fields: "
                        + ArrayConverter.bytesToHexString(
                                message.getMethodSpecificFields().getValue()));
    }

    @Override
    public void parse(UserAuthUnknownMessage message) {
        LOGGER.debug("Parsing UserAuthBannerMessage");
        parseProtocolMessageContents(message);
        message.setCompleteResultingMessage(getAlreadyParsed());
    }

    @Override
    protected void parseMessageSpecificContents(UserAuthUnknownMessage message) {
        super.parseMessageSpecificContents(message);
        parseMethodSpecificFields(message);
    }
}
