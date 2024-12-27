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
import de.rub.nds.sshattacker.core.protocol.common.SerializerStream;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class UserAuthUnknownMessageSerializer
        extends UserAuthRequestMessageSerializer<UserAuthUnknownMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    private static void serializeMethodSpecificFields(
            UserAuthUnknownMessage object, SerializerStream output) {
        byte[] methodSpecificFields = object.getMethodSpecificFields().getValue();
        LOGGER.debug(
                "Method Specific Fields: {}",
                () -> ArrayConverter.bytesToHexString(methodSpecificFields));
        output.appendBytes(methodSpecificFields);
    }

    @Override
    protected void serializeMessageSpecificContents(
            UserAuthUnknownMessage object, SerializerStream output) {
        super.serializeMessageSpecificContents(object, output);
        serializeMethodSpecificFields(object, output);
    }
}
