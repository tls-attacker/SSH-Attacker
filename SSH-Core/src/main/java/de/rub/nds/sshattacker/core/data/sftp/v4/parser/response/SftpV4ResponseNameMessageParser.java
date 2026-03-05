/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.v4.parser.response;

import de.rub.nds.sshattacker.core.data.sftp.common.parser.response.SftpResponseMessageParser;
import de.rub.nds.sshattacker.core.data.sftp.v4.message.response.SftpV4ResponseNameMessage;
import de.rub.nds.sshattacker.core.data.sftp.v4.parser.holder.SftpV4FileNameEntryParser;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class SftpV4ResponseNameMessageParser
        extends SftpResponseMessageParser<SftpV4ResponseNameMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public SftpV4ResponseNameMessageParser(byte[] array) {
        super(array);
    }

    public SftpV4ResponseNameMessageParser(byte[] array, int startPosition) {
        super(array, startPosition);
    }

    @Override
    public SftpV4ResponseNameMessage createMessage() {
        return new SftpV4ResponseNameMessage();
    }

    private void parseNameEntries() {
        int countNameEntries = parseIntField();
        message.setNameEntriesCount(countNameEntries);
        LOGGER.debug("CountNameEntries: {}", countNameEntries);

        for (int nameEntryIndex = 0, nameEntryStartPointer = getPointer();
                nameEntryIndex < message.getNameEntriesCount().getValue();
                nameEntryIndex++, nameEntryStartPointer = getPointer()) {

            SftpV4FileNameEntryParser nameEntryParser =
                    new SftpV4FileNameEntryParser(getArray(), nameEntryStartPointer);

            message.addNameEntry(nameEntryParser.parse());
            setPointer(nameEntryParser.getPointer());
        }
    }

    @Override
    protected void parseResponseSpecificContents() {
        parseNameEntries();
    }
}
