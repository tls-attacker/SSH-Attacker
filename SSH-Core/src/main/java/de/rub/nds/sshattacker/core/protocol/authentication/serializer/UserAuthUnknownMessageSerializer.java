/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.authentication.serializer;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.sshattacker.core.protocol.authentication.message.UserAuthUnknownMessage;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class UserAuthUnknownMessageSerializer
        extends UserAuthRequestMessageSerializer<UserAuthUnknownMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public UserAuthUnknownMessageSerializer(UserAuthUnknownMessage message) {
        super(message);
    }

    private void serializeMethodSpecificFields() {
        byte[] methodSpecificFields = message.getMethodSpecificFields().getValue();
        LOGGER.debug(
                "Method Specific Fields: {}",
                () -> ArrayConverter.bytesToHexString(methodSpecificFields));
        appendBytes(methodSpecificFields);
    }

    @Override
    protected void serializeMessageSpecificContents() {
        super.serializeMessageSpecificContents();
        serializeMethodSpecificFields();
    }
}
