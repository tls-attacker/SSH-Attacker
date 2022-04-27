/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.authentication.parser;

import de.rub.nds.sshattacker.core.constants.DataFormatConstants;
import de.rub.nds.sshattacker.core.protocol.authentication.AuthenticationResponse;
import de.rub.nds.sshattacker.core.protocol.authentication.message.UserAuthInfoResponseMessage;
import de.rub.nds.sshattacker.core.protocol.common.SshMessageParser;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class UserAuthInfoResponseMessageParser
        extends SshMessageParser<UserAuthInfoResponseMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public UserAuthInfoResponseMessageParser(byte[] array) {
        super(array);
    }

    public UserAuthInfoResponseMessageParser(byte[] array, int startPosition) {
        super(array, startPosition);
    }

    @Override
    protected UserAuthInfoResponseMessage createMessage() {
        return new UserAuthInfoResponseMessage();
    }

    private void parseResponses() {
        message.setNumResponses(parseIntField(DataFormatConstants.UINT32_SIZE));
        LOGGER.debug("Number of responses: " + message.getNumResponses().getValue());
        for (int i = 0; i < message.getNumResponses().getValue(); i++) {
            AuthenticationResponse temp = new AuthenticationResponse();
            temp.setResponseLength(parseIntField(DataFormatConstants.STRING_SIZE_LENGTH));
            LOGGER.debug("Response[" + i + "] length: " + temp.getResponseLength().getValue());
            temp.setResponse(parseByteString(temp.getResponseLength().getValue()));
            LOGGER.debug("Response[" + i + "]: " + temp.getResponse().getValue());
            message.getResponses().add(temp);
        }
    }

    @Override
    protected void parseMessageSpecificContents() {
        parseResponses();
    }
}
