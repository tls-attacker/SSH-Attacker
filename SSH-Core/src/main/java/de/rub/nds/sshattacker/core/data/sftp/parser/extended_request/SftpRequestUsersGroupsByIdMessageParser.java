/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.parser.extended_request;

import de.rub.nds.sshattacker.core.constants.DataFormatConstants;
import de.rub.nds.sshattacker.core.data.sftp.message.extended_request.SftpRequestUsersGroupsByIdMessage;
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
        int userIdsLength = parseIntField(DataFormatConstants.UINT32_SIZE);
        message.setUserIdsLength(userIdsLength);
        LOGGER.debug("UserIdsLength: {}", userIdsLength);
        int userIdsCount = message.getUserIdsLength().getValue() / DataFormatConstants.UINT32_SIZE;
        for (int i = 0; i < userIdsCount; i++) {
            int userId = parseIntField(DataFormatConstants.UINT32_SIZE);
            message.addUserId(userId);
            LOGGER.debug("UserId[{}]: {}", i, userId);
        }
    }

    private void parseGroupIds() {
        int groupIdsLength = parseIntField(DataFormatConstants.UINT32_SIZE);
        message.setGroupIdsLength(groupIdsLength);
        LOGGER.debug("GroupIdsLength: {}", groupIdsLength);
        int groupIdsCount =
                message.getGroupIdsLength().getValue() / DataFormatConstants.UINT32_SIZE;
        for (int i = 0; i < groupIdsCount; i++) {
            int groupId = parseIntField(DataFormatConstants.UINT32_SIZE);
            message.addGroupId(groupId);
            LOGGER.debug("GroupId[{}]: {}", i, groupId);
        }
    }

    @Override
    protected void parseRequestExtendedSpecificContents() {
        parseUserIds();
        parseGroupIds();
    }
}
