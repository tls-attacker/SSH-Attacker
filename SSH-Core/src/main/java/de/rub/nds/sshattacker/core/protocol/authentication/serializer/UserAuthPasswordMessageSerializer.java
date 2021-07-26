/**
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2021 Ruhr University Bochum, Paderborn University,
 * and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.authentication.serializer;

import de.rub.nds.sshattacker.core.constants.DataFormatConstants;
import de.rub.nds.sshattacker.core.protocol.authentication.message.UserAuthPasswordMessage;
import de.rub.nds.sshattacker.core.util.Converter;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.nio.charset.StandardCharsets;

public class UserAuthPasswordMessageSerializer extends UserAuthRequestMessageSerializer<UserAuthPasswordMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public UserAuthPasswordMessageSerializer(UserAuthPasswordMessage msg) {
        super(msg);
    }

    private void serializeChangePassword() {
        LOGGER.debug("Change password: " + Converter.byteToBoolean(msg.getChangePassword().getValue()));
        appendByte(msg.getChangePassword().getValue());
    }

    private void serializePassword() {
        LOGGER.debug("Password length: " + msg.getPasswordLength().getValue());
        appendInt(msg.getPasswordLength().getValue(), DataFormatConstants.STRING_SIZE_LENGTH);
        LOGGER.debug("Password: " + msg.getPassword().getValue());
        appendString(msg.getPassword().getValue(), StandardCharsets.UTF_8);
    }

    private void serializeNewPassword() {
        LOGGER.debug("New password length: " + msg.getNewPasswordLength().getValue());
        appendInt(msg.getNewPasswordLength().getValue(), DataFormatConstants.STRING_SIZE_LENGTH);
        LOGGER.debug("New password: " + msg.getNewPassword().getValue());
        appendString(msg.getNewPassword().getValue(), StandardCharsets.UTF_8);
    }

    @Override
    protected byte[] serializeMessageSpecificPayload() {
        super.serializeMessageSpecificPayload();
        serializeChangePassword();
        serializePassword();
        if (Converter.byteToBoolean(msg.getChangePassword().getValue())) {
            serializeNewPassword();
        }
        return getAlreadySerialized();
    }

}
