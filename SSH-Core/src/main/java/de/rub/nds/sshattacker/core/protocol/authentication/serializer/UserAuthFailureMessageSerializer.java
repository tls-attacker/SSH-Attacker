/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.authentication.serializer;

import de.rub.nds.sshattacker.core.constants.DataFormatConstants;
import de.rub.nds.sshattacker.core.protocol.authentication.message.UserAuthFailureMessage;
import de.rub.nds.sshattacker.core.protocol.common.SshMessageSerializer;
import de.rub.nds.sshattacker.core.util.Converter;
import java.nio.charset.StandardCharsets;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class UserAuthFailureMessageSerializer extends SshMessageSerializer<UserAuthFailureMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public UserAuthFailureMessageSerializer(UserAuthFailureMessage message) {
        super(message);
    }

    private void serializePossibleAuthenticationMethods() {
        LOGGER.debug(
                "Possible authentication methods length: "
                        + message.getPossibleAuthenticationMethodsLength().getValue());
        appendInt(
                message.getPossibleAuthenticationMethodsLength().getValue(),
                DataFormatConstants.STRING_SIZE_LENGTH);
        LOGGER.debug(
                "Possible authentication methods: "
                        + message.getPossibleAuthenticationMethods().getValue());
        appendString(
                message.getPossibleAuthenticationMethods().getValue(), StandardCharsets.US_ASCII);
    }

    private void serializePartialSuccess() {
        LOGGER.debug(
                "Partial success: "
                        + Converter.byteToBoolean(message.getPartialSuccess().getValue()));
        appendByte(message.getPartialSuccess().getValue());
    }

    @Override
    public void serializeMessageSpecificContents() {
        serializePossibleAuthenticationMethods();
        serializePartialSuccess();
    }

    @Override
    protected byte[] serializeBytes() {
        serializeProtocolMessageContents();
        return getAlreadySerialized();
    }
}
