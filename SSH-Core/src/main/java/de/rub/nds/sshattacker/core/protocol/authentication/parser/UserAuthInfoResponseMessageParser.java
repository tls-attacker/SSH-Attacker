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
import java.io.InputStream;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class UserAuthInfoResponseMessageParser
        extends SshMessageParser<UserAuthInfoResponseMessage> {

    private static final Logger LOGGER = LogManager.getLogger();


    public UserAuthInfoResponseMessageParser(InputStream stream) {
        super(stream);
    }

    @Override
    public void parse(UserAuthInfoResponseMessage message) {
        LOGGER.debug("Parsing UserAuthBannerMessage");
        parseProtocolMessageContents(message);
        message.setCompleteResultingMessage(getAlreadyParsed());
    }

    private void parseResponseEntries(UserAuthInfoResponseMessage message) {
        message.setResponseEntryCount(parseIntField(DataFormatConstants.UINT32_SIZE));
        LOGGER.debug("Number of response entries: {}", message.getResponseEntryCount().getValue());
        for (int i = 0; i < message.getResponseEntryCount().getValue(); i++) {
            AuthenticationResponse.ResponseEntry entry = new AuthenticationResponse.ResponseEntry();
            entry.setResponseLength(parseIntField(DataFormatConstants.STRING_SIZE_LENGTH));
            LOGGER.debug("Response entry [{}] length: {}", i, entry.getResponseLength().getValue());
            entry.setResponse(parseByteString(entry.getResponseLength().getValue()));
            LOGGER.debug("Response entry [{}]: {}", i, entry.getResponse().getValue());
            message.getResponse().add(entry);
        }
    }

    @Override
    protected void parseMessageSpecificContents(UserAuthInfoResponseMessage message) {
        parseResponseEntries(message);
    }
}
