/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.authentication.parser;

import de.rub.nds.sshattacker.core.constants.DataFormatConstants;
import de.rub.nds.sshattacker.core.protocol.authentication.message.UserAuthPasswordMessage;
import de.rub.nds.sshattacker.core.util.Converter;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class UserAuthPasswordMessageParser
        extends UserAuthRequestMessageParser<UserAuthPasswordMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    /*
        public UserAuthPasswordMessageParser(byte[] array) {
            super(array);
        }
        public UserAuthPasswordMessageParser(byte[] array, int startPosition) {
            super(array, startPosition);
        }

    */

    public UserAuthPasswordMessageParser(InputStream stream) {
        super(stream);
    }

    /*
        @Override
        public UserAuthPasswordMessage createMessage() {
            return new UserAuthPasswordMessage();
        }
    */

    @Override
    public void parse(UserAuthPasswordMessage message) {
        LOGGER.debug("Parsing UserAuthBannerMessage");
        parseProtocolMessageContents(message);
        message.setCompleteResultingMessage(getAlreadyParsed());
    }

    private void parseChangePassword(UserAuthPasswordMessage message) {
        message.setChangePassword(parseByteField(1));
        LOGGER.debug("Change password: {}", message.getChangePassword().getValue());
    }

    private void parsePassword(UserAuthPasswordMessage message) {
        message.setPasswordLength(parseIntField(DataFormatConstants.STRING_SIZE_LENGTH));
        LOGGER.debug("Password length: {}", message.getPasswordLength().getValue());
        message.setPassword(
                parseByteString(message.getPasswordLength().getValue(), StandardCharsets.UTF_8));
        LOGGER.debug("Password: {}", message.getPassword().getValue());
    }

    private void parseNewPassword(UserAuthPasswordMessage message) {
        message.setNewPasswordLength(parseIntField(DataFormatConstants.STRING_SIZE_LENGTH));
        LOGGER.debug("New password length: {}", message.getNewPasswordLength().getValue());
        message.setNewPassword(
                parseByteString(message.getNewPasswordLength().getValue(), StandardCharsets.UTF_8));
        LOGGER.debug("New password: {}", message.getNewPassword().getValue());
    }

    @Override
    protected void parseMessageSpecificContents(UserAuthPasswordMessage message) {
        super.parseMessageSpecificContents(message);
        parseChangePassword(message);
        parsePassword(message);
        if (Converter.byteToBoolean(message.getChangePassword().getValue())) {
            parseNewPassword(message);
        }
    }
}
