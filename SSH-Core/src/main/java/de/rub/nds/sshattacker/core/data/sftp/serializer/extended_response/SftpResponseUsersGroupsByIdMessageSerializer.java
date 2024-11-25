/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.serializer.extended_response;

import de.rub.nds.sshattacker.core.constants.DataFormatConstants;
import de.rub.nds.sshattacker.core.data.sftp.message.extended_response.SftpResponseUsersGroupsByIdMessage;
import de.rub.nds.sshattacker.core.data.sftp.serializer.response.SftpResponseMessageSerializer;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class SftpResponseUsersGroupsByIdMessageSerializer
        extends SftpResponseMessageSerializer<SftpResponseUsersGroupsByIdMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public SftpResponseUsersGroupsByIdMessageSerializer(
            SftpResponseUsersGroupsByIdMessage message) {
        super(message);
    }

    private void serializeUserNames() {
        Integer userNamesLength = message.getUserNamesLength().getValue();
        LOGGER.debug("UserNames length: {}", userNamesLength);
        appendInt(userNamesLength, DataFormatConstants.STRING_SIZE_LENGTH);

        message.getUserNames()
                .forEach(
                        userName ->
                                appendBytes(userName.getHandler(null).getSerializer().serialize()));
    }

    private void serializeGroupNames() {
        Integer groupNamesLength = message.getGroupNamesLength().getValue();
        LOGGER.debug("GroupNames length: {}", groupNamesLength);
        appendInt(groupNamesLength, DataFormatConstants.STRING_SIZE_LENGTH);

        message.getGroupNames()
                .forEach(
                        groupName ->
                                appendBytes(
                                        groupName.getHandler(null).getSerializer().serialize()));
    }

    @Override
    protected void serializeResponseSpecificContents() {
        serializeUserNames();
        serializeGroupNames();
    }
}
