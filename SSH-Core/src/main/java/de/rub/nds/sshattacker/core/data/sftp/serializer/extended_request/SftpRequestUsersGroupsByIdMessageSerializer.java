/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.serializer.extended_request;

import de.rub.nds.sshattacker.core.data.sftp.message.extended_request.SftpRequestUsersGroupsByIdMessage;
import de.rub.nds.sshattacker.core.protocol.common.SerializerStream;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class SftpRequestUsersGroupsByIdMessageSerializer
        extends SftpRequestExtendedMessageSerializer<SftpRequestUsersGroupsByIdMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    private static void serializeUserIdsLength(
            SftpRequestUsersGroupsByIdMessage object, SerializerStream output) {
        Integer userIdsLength = object.getUserIdsLength().getValue();
        LOGGER.debug("UserIdsLength: {}", userIdsLength);
        output.appendInt(userIdsLength);

        object.getUserIds().forEach(userId -> output.appendBytes(userId.serialize()));
    }

    private static void serializeGroupIdsLength(
            SftpRequestUsersGroupsByIdMessage object, SerializerStream output) {
        Integer groupIdsLength = object.getGroupIdsLength().getValue();
        LOGGER.debug("GroupIdsLength: {}", groupIdsLength);
        output.appendInt(groupIdsLength);

        object.getGroupIds().forEach(groupId -> output.appendBytes(groupId.serialize()));
    }

    @Override
    protected void serializeRequestExtendedSpecificContents(
            SftpRequestUsersGroupsByIdMessage object, SerializerStream output) {
        serializeUserIdsLength(object, output);
        serializeGroupIdsLength(object, output);
    }
}
