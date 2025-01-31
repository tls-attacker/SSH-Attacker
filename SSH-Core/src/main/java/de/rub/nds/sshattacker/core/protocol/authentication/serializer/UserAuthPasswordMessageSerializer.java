/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.authentication.serializer;

import static de.rub.nds.modifiablevariable.util.StringUtil.backslashEscapeString;

import de.rub.nds.sshattacker.core.protocol.authentication.message.UserAuthPasswordMessage;
import de.rub.nds.sshattacker.core.protocol.common.SerializerStream;
import de.rub.nds.sshattacker.core.util.Converter;
import java.nio.charset.StandardCharsets;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class UserAuthPasswordMessageSerializer
        extends UserAuthRequestMessageSerializer<UserAuthPasswordMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    private static void serializeChangePassword(
            UserAuthPasswordMessage object, SerializerStream output) {
        Byte changePassword = object.getChangePassword().getValue();
        LOGGER.debug("Change password: {}", () -> Converter.byteToBoolean(changePassword));
        output.appendByte(changePassword);
    }

    private static void serializePassword(UserAuthPasswordMessage object, SerializerStream output) {
        Integer passwordLength = object.getPasswordLength().getValue();
        LOGGER.debug("Password length: {}", passwordLength);
        output.appendInt(passwordLength);
        String password = object.getPassword().getValue();
        LOGGER.debug("Password: {}", () -> backslashEscapeString(password));
        output.appendString(password, StandardCharsets.UTF_8);
    }

    private static void serializeNewPassword(
            UserAuthPasswordMessage object, SerializerStream output) {
        Integer newPasswordLength = object.getNewPasswordLength().getValue();
        LOGGER.debug("New password length: {}", newPasswordLength);
        output.appendInt(newPasswordLength);
        String newPassword = object.getNewPassword().getValue();
        LOGGER.debug("New password: {}", () -> backslashEscapeString(newPassword));
        output.appendString(newPassword, StandardCharsets.UTF_8);
    }

    @Override
    protected void serializeMessageSpecificContents(
            UserAuthPasswordMessage object, SerializerStream output) {
        super.serializeMessageSpecificContents(object, output);
        serializeChangePassword(object, output);
        serializePassword(object, output);
        if (Converter.byteToBoolean(object.getChangePassword().getValue())) {
            serializeNewPassword(object, output);
        }
    }
}
