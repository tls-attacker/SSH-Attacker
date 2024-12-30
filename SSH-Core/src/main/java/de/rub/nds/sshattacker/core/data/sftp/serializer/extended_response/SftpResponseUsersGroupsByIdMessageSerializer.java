/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.serializer.extended_response;

import de.rub.nds.sshattacker.core.data.sftp.message.extended_response.SftpResponseUsersGroupsByIdMessage;
import de.rub.nds.sshattacker.core.data.sftp.serializer.response.SftpResponseMessageSerializer;
import de.rub.nds.sshattacker.core.protocol.common.SerializerStream;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class SftpResponseUsersGroupsByIdMessageSerializer
        extends SftpResponseMessageSerializer<SftpResponseUsersGroupsByIdMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    private static void serializeUserNames(
            SftpResponseUsersGroupsByIdMessage object, SerializerStream output) {
        Integer userNamesLength = object.getUserNamesLength().getValue();
        LOGGER.debug("UserNames length: {}", userNamesLength);
        output.appendInt(userNamesLength);

        object.getUserNames().forEach(userName -> output.appendBytes(userName.serialize()));
    }

    private static void serializeGroupNames(
            SftpResponseUsersGroupsByIdMessage object, SerializerStream output) {
        Integer groupNamesLength = object.getGroupNamesLength().getValue();
        LOGGER.debug("GroupNames length: {}", groupNamesLength);
        output.appendInt(groupNamesLength);

        object.getGroupNames().forEach(groupName -> output.appendBytes(groupName.serialize()));
    }

    @Override
    protected void serializeResponseSpecificContents(
            SftpResponseUsersGroupsByIdMessage object, SerializerStream output) {
        serializeUserNames(object, output);
        serializeGroupNames(object, output);
    }
}
