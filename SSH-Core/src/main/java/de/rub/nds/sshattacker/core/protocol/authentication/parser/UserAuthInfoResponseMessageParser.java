/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.authentication.parser;

import de.rub.nds.sshattacker.core.protocol.authentication.message.UserAuthInfoResponseMessage;
import de.rub.nds.sshattacker.core.protocol.authentication.parser.holder.AuthenticationResponseEntryParser;
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

    private void parseResponseEntries() {
        int responseEntriesCount = parseIntField();
        message.setResponseEntriesCount(responseEntriesCount);
        LOGGER.debug("Number of response entries: {}", responseEntriesCount);

        for (int responseEntryIdx = 0, responseEntryStartPointer = getPointer();
                responseEntryIdx < responseEntriesCount;
                responseEntryIdx++, responseEntryStartPointer = getPointer()) {

            AuthenticationResponseEntryParser responseEntryParser =
                    new AuthenticationResponseEntryParser(getArray(), responseEntryStartPointer);

            message.addResponseEntry(responseEntryParser.parse());
            setPointer(responseEntryParser.getPointer());
        }
    }

    @Override
    protected void parseMessageSpecificContents() {
        parseResponseEntries();
    }
}
