/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.serializer.extended_response;

import static de.rub.nds.modifiablevariable.util.StringUtil.backslashEscapeString;

import de.rub.nds.modifiablevariable.string.ModifiableString;
import de.rub.nds.sshattacker.core.constants.DataFormatConstants;
import de.rub.nds.sshattacker.core.data.sftp.message.extended_response.SftpResponseUsersGroupsByIdMessage;
import de.rub.nds.sshattacker.core.data.sftp.serializer.response.SftpResponseMessageSerializer;
import java.nio.charset.StandardCharsets;
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
        for (ModifiableString userName : message.getUserNames()) {
            LOGGER.debug("UserName length: {}", userName.getValue().length());
            appendInt(userName.getValue().length(), DataFormatConstants.STRING_SIZE_LENGTH);
            LOGGER.debug("UserName: {}", () -> backslashEscapeString(userName.getValue()));
            appendString(userName.getValue(), StandardCharsets.UTF_8);
        }
    }

    private void serializeGroupNames() {
        Integer groupNamesLength = message.getGroupNamesLength().getValue();
        LOGGER.debug("GroupNames length: {}", groupNamesLength);
        appendInt(groupNamesLength, DataFormatConstants.STRING_SIZE_LENGTH);
        for (ModifiableString userName : message.getGroupNames()) {
            LOGGER.debug("GroupName length: {}", userName.getValue().length());
            appendInt(userName.getValue().length(), DataFormatConstants.STRING_SIZE_LENGTH);
            LOGGER.debug("GroupName: {}", () -> backslashEscapeString(userName.getValue()));
            appendString(userName.getValue(), StandardCharsets.UTF_8);
        }
    }

    @Override
    protected void serializeResponseSpecificContents() {
        serializeUserNames();
        serializeGroupNames();
    }
}
