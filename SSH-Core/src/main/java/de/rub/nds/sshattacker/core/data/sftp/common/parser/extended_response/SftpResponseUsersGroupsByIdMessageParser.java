/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.common.parser.extended_response;

import de.rub.nds.sshattacker.core.data.sftp.common.message.extended_response.SftpResponseUsersGroupsByIdMessage;
import de.rub.nds.sshattacker.core.data.sftp.common.parser.holder.SftpNameEntryParser;
import de.rub.nds.sshattacker.core.data.sftp.common.parser.response.SftpResponseMessageParser;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class SftpResponseUsersGroupsByIdMessageParser
        extends SftpResponseMessageParser<SftpResponseUsersGroupsByIdMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public SftpResponseUsersGroupsByIdMessageParser(byte[] array) {
        super(array);
    }

    public SftpResponseUsersGroupsByIdMessageParser(byte[] array, int startPosition) {
        super(array, startPosition);
    }

    @Override
    public SftpResponseUsersGroupsByIdMessage createMessage() {
        return new SftpResponseUsersGroupsByIdMessage();
    }

    private void parseUserNames() {
        int userNamesLength = parseIntField();
        message.setUserNamesLength(userNamesLength);
        LOGGER.debug("UserNames length: {}", userNamesLength);
        int oldPointer = getPointer();
        while (getPointer() - oldPointer < userNamesLength) {
            SftpNameEntryParser nameEntryParser = new SftpNameEntryParser(getArray(), getPointer());

            message.addUserName(nameEntryParser.parse());
            setPointer(nameEntryParser.getPointer());
        }
    }

    private void parseGroupNames() {
        int groupNamesLength = parseIntField();
        message.setGroupNamesLength(groupNamesLength);
        LOGGER.debug("GroupNames length: {}", groupNamesLength);
        int oldPointer = getPointer();
        while (getPointer() - oldPointer < groupNamesLength) {
            SftpNameEntryParser nameEntryParser = new SftpNameEntryParser(getArray(), getPointer());

            message.addGroupName(nameEntryParser.parse());
            setPointer(nameEntryParser.getPointer());
        }
    }

    @Override
    protected void parseResponseSpecificContents() {
        parseUserNames();
        parseGroupNames();
    }
}
