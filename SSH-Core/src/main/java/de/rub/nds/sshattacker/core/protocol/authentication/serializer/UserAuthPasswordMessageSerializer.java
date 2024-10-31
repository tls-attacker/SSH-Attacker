/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.authentication.serializer;

import de.rub.nds.sshattacker.core.constants.DataFormatConstants;
import de.rub.nds.sshattacker.core.protocol.authentication.message.UserAuthPasswordMessage;
import de.rub.nds.sshattacker.core.util.Converter;
import java.nio.charset.StandardCharsets;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class UserAuthPasswordMessageSerializer
        extends UserAuthRequestMessageSerializer<UserAuthPasswordMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public UserAuthPasswordMessageSerializer(UserAuthPasswordMessage message) {
        super(message);
    }

    private void serializeChangePassword() {
        LOGGER.debug(
                "Change password: {}",
                Converter.byteToBoolean(message.getChangePassword().getValue()));
        appendByte(message.getChangePassword().getValue());
    }

    private void serializePassword() {
        LOGGER.debug("Password length: {}", message.getPasswordLength().getValue());
        appendInt(message.getPasswordLength().getValue(), DataFormatConstants.STRING_SIZE_LENGTH);
        LOGGER.debug("Password: {}", message.getPassword().getValue());
        appendString(message.getPassword().getValue(), StandardCharsets.UTF_8);
    }

    private void serializeNewPassword() {
        LOGGER.debug("New password length: {}", message.getNewPasswordLength().getValue());
        appendInt(
                message.getNewPasswordLength().getValue(), DataFormatConstants.STRING_SIZE_LENGTH);
        LOGGER.debug("New password: {}", message.getNewPassword().getValue());
        appendString(message.getNewPassword().getValue(), StandardCharsets.UTF_8);
    }

    @Override
    protected void serializeMessageSpecificContents() {
        super.serializeMessageSpecificContents();
        serializeChangePassword();
        serializePassword();
        if (Converter.byteToBoolean(message.getChangePassword().getValue())) {
            serializeNewPassword();
        }
    }
}
