/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2021 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.authentication.parser;

import de.rub.nds.sshattacker.core.constants.DataFormatConstants;
import de.rub.nds.sshattacker.core.protocol.authentication.message.UserAuthPasswordMessage;
import de.rub.nds.sshattacker.core.protocol.common.SshMessageParser;
import java.nio.charset.StandardCharsets;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class UserAuthPasswordMessageParser extends SshMessageParser<UserAuthPasswordMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public UserAuthPasswordMessageParser(byte[] array, int startPosition) {
        super(array, startPosition);
    }

    @Override
    public UserAuthPasswordMessage createMessage() {
        return new UserAuthPasswordMessage();
    }

    private void parseUserName() {
        message.setUserNameLength(parseIntField(DataFormatConstants.STRING_SIZE_LENGTH));
        LOGGER.debug("Username length: " + message.getUserNameLength().getValue());
        message.setUserName(
                parseByteString(message.getUserNameLength().getValue(), StandardCharsets.US_ASCII));
        LOGGER.debug("Username: " + message.getUserName().getValue());
    }

    private void parseServiceName() {
        message.setServiceNameLength(parseIntField(DataFormatConstants.STRING_SIZE_LENGTH));
        LOGGER.debug("Servicename length: " + message.getServiceNameLength().getValue());
        message.setServiceName(
                parseByteString(
                        message.getServiceNameLength().getValue(), StandardCharsets.US_ASCII));
        LOGGER.debug("Servicename: " + message.getServiceName().getValue());
    }

    private void parseChangePassword() {
        message.setChangePassword(parseByteField(1));
        LOGGER.debug("Change password: " + message.getChangePassword().getValue());
    }

    private void parsePassword() {
        message.setPasswordLength(parseIntField(DataFormatConstants.STRING_SIZE_LENGTH));
        LOGGER.debug("Password length: " + message.getPasswordLength().getValue());
        message.setPassword(
                parseByteString(message.getPasswordLength().getValue(), StandardCharsets.UTF_8));
        LOGGER.debug("Password: " + message.getPassword().getValue());
    }

    @Override
    protected void parseMessageSpecificContents() {
        parseUserName();
        parseServiceName();
        // String "password" has no usage
        LOGGER.debug(
                parseByteString(
                                parseIntField(DataFormatConstants.STRING_SIZE_LENGTH),
                                StandardCharsets.US_ASCII)
                        .toString());
        parseChangePassword();
        parsePassword();
    }
}
