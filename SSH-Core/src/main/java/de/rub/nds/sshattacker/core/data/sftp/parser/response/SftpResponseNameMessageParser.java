/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.parser.response;

import de.rub.nds.sshattacker.core.constants.DataFormatConstants;
import de.rub.nds.sshattacker.core.data.sftp.message.response.SftpResponseNameMessage;
import de.rub.nds.sshattacker.core.data.sftp.parser.holder.SftpFileNameEntryParser;
import de.rub.nds.sshattacker.core.workflow.chooser.Chooser;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class SftpResponseNameMessageParser
        extends SftpResponseMessageParser<SftpResponseNameMessage> {

    private static final Logger LOGGER = LogManager.getLogger();
    private final Chooser chooser;

    public SftpResponseNameMessageParser(byte[] array, Chooser chooser) {
        super(array);
        this.chooser = chooser;
    }

    public SftpResponseNameMessageParser(byte[] array, int startPosition, Chooser chooser) {
        super(array, startPosition);
        this.chooser = chooser;
    }

    @Override
    public SftpResponseNameMessage createMessage() {
        return new SftpResponseNameMessage();
    }

    private void parseNameEntries() {
        int countNameEntries = parseIntField(DataFormatConstants.UINT32_SIZE);
        message.setNameEntriesCount(countNameEntries);
        LOGGER.debug("CountNameEntries: {}", countNameEntries);

        for (int nameEntryIndex = 0, nameEntryStartPointer = getPointer();
                nameEntryIndex < message.getNameEntriesCount().getValue();
                nameEntryIndex++, nameEntryStartPointer = getPointer()) {

            SftpFileNameEntryParser nameEntryParser =
                    new SftpFileNameEntryParser(getArray(), nameEntryStartPointer, chooser);

            message.addNameEntry(nameEntryParser.parse());
            setPointer(nameEntryParser.getPointer());
        }
    }

    @Override
    protected void parseResponseSpecificContents() {
        parseNameEntries();
    }
}
