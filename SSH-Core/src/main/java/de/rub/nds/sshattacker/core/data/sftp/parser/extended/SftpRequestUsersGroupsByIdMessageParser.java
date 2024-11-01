/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.parser.extended;

import de.rub.nds.sshattacker.core.constants.DataFormatConstants;
import de.rub.nds.sshattacker.core.data.sftp.message.extended.SftpRequestUsersGroupsByIdMessage;
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
        message.setUserIdsLength(parseIntField(DataFormatConstants.UINT32_SIZE));
        LOGGER.debug("UserIdsLength: {}", message.getUserIdsLength().getValue());
        int userIdsCount = message.getUserIdsLength().getValue() / DataFormatConstants.UINT32_SIZE;
        for (int i = 0; i < userIdsCount; i++) {
            message.addUserId(parseIntField(DataFormatConstants.UINT32_SIZE));
            LOGGER.debug("UserId[{}]: {}", i, message.getUserIdsLength().getValue());
        }
    }

    private void parseGroupIds() {
        message.setGroupIdsLength(parseIntField(DataFormatConstants.UINT32_SIZE));
        LOGGER.debug("GroupIdsLength: {}", message.getGroupIdsLength().getValue());
        int groupIdsCount =
                message.getGroupIdsLength().getValue() / DataFormatConstants.UINT32_SIZE;
        for (int i = 0; i < groupIdsCount; i++) {
            message.addGroupId(parseIntField(DataFormatConstants.UINT32_SIZE));
            LOGGER.debug("GroupId[{}]: {}", i, message.getGroupIdsLength().getValue());
        }
    }

    @Override
    protected void parseRequestExtendedSpecificContents() {
        parseUserIds();
        parseGroupIds();
    }
}
