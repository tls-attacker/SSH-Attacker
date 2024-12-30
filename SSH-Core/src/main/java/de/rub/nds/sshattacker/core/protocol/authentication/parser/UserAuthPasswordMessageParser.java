/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.authentication.parser;

import de.rub.nds.sshattacker.core.protocol.authentication.message.UserAuthPasswordMessage;
import de.rub.nds.sshattacker.core.util.Converter;
import java.nio.charset.StandardCharsets;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class UserAuthPasswordMessageParser
        extends UserAuthRequestMessageParser<UserAuthPasswordMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public UserAuthPasswordMessageParser(byte[] array) {
        super(array);
    }

    public UserAuthPasswordMessageParser(byte[] array, int startPosition) {
        super(array, startPosition);
    }

    @Override
    public UserAuthPasswordMessage createMessage() {
        return new UserAuthPasswordMessage();
    }

    private void parseChangePassword() {
        byte changePassword = parseByteField();
        message.setChangePassword(changePassword);
        LOGGER.debug("Change password: {}", changePassword);
    }

    private void parsePassword() {
        int passwordLength = parseIntField();
        message.setPasswordLength(passwordLength);
        LOGGER.debug("Password length: {}", passwordLength);
        String password = parseByteString(passwordLength, StandardCharsets.UTF_8);
        message.setPassword(password);
        LOGGER.debug("Password: {}", password);
    }

    private void parseNewPassword() {
        int newPasswordLength = parseIntField();
        message.setNewPasswordLength(newPasswordLength);
        LOGGER.debug("New password length: {}", newPasswordLength);
        String newPassword = parseByteString(newPasswordLength, StandardCharsets.UTF_8);
        message.setNewPassword(newPassword);
        LOGGER.debug("New password: {}", newPassword);
    }

    @Override
    protected void parseMessageSpecificContents() {
        super.parseMessageSpecificContents();
        parseChangePassword();
        parsePassword();
        if (Converter.byteToBoolean(message.getChangePassword().getValue())) {
            parseNewPassword();
        }
    }
}
