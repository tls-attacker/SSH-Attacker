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

import de.rub.nds.sshattacker.core.constants.AuthenticationMethod;
import de.rub.nds.sshattacker.core.protocol.authentication.message.UserAuthPasswordMessage;
import de.rub.nds.sshattacker.core.protocol.common.MessageSerializer;
import de.rub.nds.sshattacker.core.util.Converter;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class UserAuthPasswordMessageSerializer extends MessageSerializer<UserAuthPasswordMessage> {

    private final UserAuthPasswordMessage msg;
    private static final Logger LOGGER = LogManager.getLogger();

    public UserAuthPasswordMessageSerializer(UserAuthPasswordMessage msg) {
        super(msg);
        this.msg = msg;
    }

    @Override
    protected byte[] serializeMessageSpecificPayload() {
        LOGGER.debug("username: " + msg.getUsername().getValue());
        appendBytes(Converter.stringToLengthPrefixedBinaryString(msg.getUsername().getValue()));
        LOGGER.debug("servicename: " + msg.getServicename().getValue());
        appendBytes(Converter.stringToLengthPrefixedBinaryString(msg.getServicename().getValue()));
        appendBytes(Converter.stringToLengthPrefixedBinaryString(AuthenticationMethod.PASSWORD.toString()));
        LOGGER.debug("expectResponse: " + msg.getExpectResponse().getValue());
        appendByte(msg.getExpectResponse().getValue());
        LOGGER.debug("password: " + msg.getPassword().getValue());
        appendBytes(Converter.stringToLengthPrefixedBinaryString(msg.getPassword().getValue()));
        return getAlreadySerialized();
    }

}
