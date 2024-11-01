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
        message.setCountNameEntries(parseIntField(DataFormatConstants.UINT32_SIZE));
        LOGGER.debug("CountNameEntries: {}", message.getCountNameEntries().getValue());

        for (int nameEntryIndex = 0, nameEntryStartPointer = getPointer();
                nameEntryIndex < message.getCountNameEntries().getValue();
                nameEntryIndex++, nameEntryStartPointer = getPointer()) {

            SftpResponseNameEntryParser nameEntryParser =
                    new SftpResponseNameEntryParser(getArray(), nameEntryStartPointer);

            message.addNameEntry(nameEntryParser.parse());
            setPointer(nameEntryParser.getPointer());
        }
    }

    @Override
    protected void parseResponseSpecificContents() {
        parseNameEntries();
    }
}
