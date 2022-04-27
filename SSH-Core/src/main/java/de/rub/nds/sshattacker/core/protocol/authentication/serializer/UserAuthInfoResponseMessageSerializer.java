/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.authentication.serializer;

import de.rub.nds.sshattacker.core.constants.DataFormatConstants;
import de.rub.nds.sshattacker.core.protocol.authentication.AuthenticationResponse;
import de.rub.nds.sshattacker.core.protocol.authentication.message.UserAuthInfoResponseMessage;
import de.rub.nds.sshattacker.core.protocol.common.SshMessageSerializer;
import java.nio.charset.StandardCharsets;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class UserAuthInfoResponseMessageSerializer
        extends SshMessageSerializer<UserAuthInfoResponseMessage> {
    private static final Logger LOGGER = LogManager.getLogger();

    public UserAuthInfoResponseMessageSerializer(UserAuthInfoResponseMessage message) {
        super(message);
    }

    private void serializeResponses() {
        LOGGER.debug("Number of responses: " + message.getNumResponses().getValue());
        appendInt(message.getNumResponses().getValue(), DataFormatConstants.UINT32_SIZE);

        for (int i = 0; i < message.getNumResponses().getValue(); i++) {
            AuthenticationResponse temp = message.getResponses().get(i);
            LOGGER.debug("Response[" + i + "] length: " + temp.getResponseLength().getValue());
            appendInt(temp.getResponseLength().getValue(), DataFormatConstants.UINT32_SIZE);
            LOGGER.debug("Response[" + i + "]: " + temp.getResponse().getValue());
            appendString(temp.getResponse().getValue(), StandardCharsets.UTF_8);
        }
    }

    @Override
    public void serializeMessageSpecificContents() {
        serializeResponses();
    }
}
