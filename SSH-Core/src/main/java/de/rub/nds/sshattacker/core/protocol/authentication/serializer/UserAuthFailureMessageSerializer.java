/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.authentication.serializer;

import de.rub.nds.sshattacker.core.protocol.authentication.message.UserAuthFailureMessage;
import de.rub.nds.sshattacker.core.protocol.common.SerializerStream;
import de.rub.nds.sshattacker.core.protocol.common.SshMessageSerializer;
import de.rub.nds.sshattacker.core.util.Converter;
import java.nio.charset.StandardCharsets;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class UserAuthFailureMessageSerializer extends SshMessageSerializer<UserAuthFailureMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    private static void serializePossibleAuthenticationMethods(
            UserAuthFailureMessage object, SerializerStream output) {
        Integer possibleAuthenticationMethodsLength =
                object.getPossibleAuthenticationMethodsLength().getValue();
        LOGGER.debug(
                "Possible authentication methods length: {}", possibleAuthenticationMethodsLength);
        output.appendInt(possibleAuthenticationMethodsLength);
        String possibleAuthenticationMethods = object.getPossibleAuthenticationMethods().getValue();
        LOGGER.debug("Possible authentication methods: {}", possibleAuthenticationMethods);
        output.appendString(possibleAuthenticationMethods, StandardCharsets.US_ASCII);
    }

    private static void serializePartialSuccess(
            UserAuthFailureMessage object, SerializerStream output) {
        Byte partialSuccess = object.getPartialSuccess().getValue();
        LOGGER.debug("Partial success: {}", () -> Converter.byteToBoolean(partialSuccess));
        output.appendByte(partialSuccess);
    }

    @Override
    protected void serializeMessageSpecificContents(
            UserAuthFailureMessage object, SerializerStream output) {
        serializePossibleAuthenticationMethods(object, output);
        serializePartialSuccess(object, output);
    }
}
