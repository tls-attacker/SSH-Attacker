/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.serializer.extended_request;

import de.rub.nds.sshattacker.core.constants.DataFormatConstants;
import de.rub.nds.sshattacker.core.data.sftp.message.extended_request.SftpRequestUsersGroupsByIdMessage;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class SftpRequestUsersGroupsByIdMessageSerializer
        extends SftpRequestExtendedMessageSerializer<SftpRequestUsersGroupsByIdMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public SftpRequestUsersGroupsByIdMessageSerializer(SftpRequestUsersGroupsByIdMessage message) {
        super(message);
    }

    private void serializeUserIdsLength() {
        Integer userIdsLength = message.getUserIdsLength().getValue();
        LOGGER.debug("UserIdsLength: {}", userIdsLength);
        appendInt(userIdsLength, DataFormatConstants.UINT32_SIZE);

        message.getUserIds()
                .forEach(
                        userId -> appendBytes(userId.getHandler(null).getSerializer().serialize()));
    }

    private void serializeGroupIdsLength() {
        Integer groupIdsLength = message.getGroupIdsLength().getValue();
        LOGGER.debug("GroupIdsLength: {}", groupIdsLength);
        appendInt(groupIdsLength, DataFormatConstants.UINT32_SIZE);

        message.getGroupIds()
                .forEach(
                        groupId ->
                                appendBytes(groupId.getHandler(null).getSerializer().serialize()));
    }

    @Override
    protected void serializeRequestExtendedSpecificContents() {
        serializeUserIdsLength();
        serializeGroupIdsLength();
    }
}
