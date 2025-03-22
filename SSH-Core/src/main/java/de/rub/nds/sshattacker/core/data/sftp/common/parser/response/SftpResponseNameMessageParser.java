/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.common.parser.response;

import de.rub.nds.sshattacker.core.data.sftp.common.message.response.SftpResponseNameMessage;
import de.rub.nds.sshattacker.core.data.sftp.common.parser.holder.SftpFileNameEntryParser;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class SftpResponseNameMessageParser
        extends SftpResponseMessageParser<SftpResponseNameMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public SftpResponseNameMessageParser(byte[] array) {
        super(array);
    }

    public SftpResponseNameMessageParser(byte[] array, int startPosition) {
        super(array, startPosition);
    }

    @Override
    public SftpResponseNameMessage createMessage() {
        return new SftpResponseNameMessage();
    }

    private void parseNameEntries() {
        int countNameEntries = parseIntField();
        message.setNameEntriesCount(countNameEntries);
        LOGGER.debug("CountNameEntries: {}", countNameEntries);

        for (int nameEntryIndex = 0, nameEntryStartPointer = getPointer();
                nameEntryIndex < message.getNameEntriesCount().getValue();
                nameEntryIndex++, nameEntryStartPointer = getPointer()) {

            SftpFileNameEntryParser nameEntryParser =
                    new SftpFileNameEntryParser(getArray(), nameEntryStartPointer);

            message.addNameEntry(nameEntryParser.parse());
            setPointer(nameEntryParser.getPointer());
        }
    }

    @Override
    protected void parseResponseSpecificContents() {
        parseNameEntries();
    }
}
