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
        LOGGER.debug("UserIdsLength: {}", message.getUserIdsLength().getValue());
        appendInt(message.getUserIdsLength().getValue(), DataFormatConstants.UINT32_SIZE);

        for (int i = 0; i < message.getUserIds().size(); i++) {
            LOGGER.debug("UserId[{}]: {}", i, message.getUserIdsLength().getValue());
            appendInt(message.getUserIdsLength().getValue(), DataFormatConstants.UINT32_SIZE);
        }
    }

    private void serializeGroupIdsLength() {
        LOGGER.debug("GroupIdsLength: {}", message.getGroupIdsLength().getValue());
        appendInt(message.getGroupIdsLength().getValue(), DataFormatConstants.UINT32_SIZE);

        for (int i = 0; i < message.getGroupIds().size(); i++) {
            LOGGER.debug("GroupId[{}]: {}", i, message.getGroupIdsLength().getValue());
            appendInt(message.getGroupIdsLength().getValue(), DataFormatConstants.UINT32_SIZE);
        }
    }

    @Override
    protected void serializeRequestExtendedSpecificContents() {
        serializeUserIdsLength();
        serializeGroupIdsLength();
    }
}
