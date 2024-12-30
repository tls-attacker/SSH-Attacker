/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.parser.extended_request;

import de.rub.nds.sshattacker.core.data.sftp.message.extended_request.SftpRequestUsersGroupsByIdMessage;
import de.rub.nds.sshattacker.core.data.sftp.parser.holder.SftpIdEntryParser;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class SftpRequestUsersGroupsByIdMessageParser
        extends SftpRequestExtendedMessageParser<SftpRequestUsersGroupsByIdMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public SftpRequestUsersGroupsByIdMessageParser(byte[] array) {
        super(array);
    }

    public SftpRequestUsersGroupsByIdMessageParser(byte[] array, int startPosition) {
        super(array, startPosition);
    }

    @Override
    protected SftpRequestUsersGroupsByIdMessage createMessage() {
        return new SftpRequestUsersGroupsByIdMessage();
    }

    private void parseUserIds() {
        int userIdsLength = parseIntField();
        message.setUserIdsLength(userIdsLength);
        LOGGER.debug("UserIdsLength: {}", userIdsLength);

        int oldPointer = getPointer();
        while (getPointer() - oldPointer < userIdsLength) {
            SftpIdEntryParser idEntryParser = new SftpIdEntryParser(getArray(), getPointer());

            message.addUserId(idEntryParser.parse());
            setPointer(idEntryParser.getPointer());
        }
    }

    private void parseGroupIds() {
        int groupIdsLength = parseIntField();
        message.setGroupIdsLength(groupIdsLength);
        LOGGER.debug("GroupIdsLength: {}", groupIdsLength);
        int oldPointer = getPointer();
        while (getPointer() - oldPointer < groupIdsLength) {
            SftpIdEntryParser idEntryParser = new SftpIdEntryParser(getArray(), getPointer());

            message.addGroupId(idEntryParser.parse());
            setPointer(idEntryParser.getPointer());
        }
    }

    @Override
    protected void parseRequestExtendedSpecificContents() {
        parseUserIds();
        parseGroupIds();
    }
}
