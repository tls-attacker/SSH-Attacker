/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.parser.extended_response;

import static de.rub.nds.modifiablevariable.util.StringUtil.backslashEscapeString;

import de.rub.nds.sshattacker.core.constants.DataFormatConstants;
import de.rub.nds.sshattacker.core.data.sftp.message.extended_response.SftpResponseUsersGroupsByIdMessage;
import de.rub.nds.sshattacker.core.data.sftp.parser.response.SftpResponseMessageParser;
import java.nio.charset.StandardCharsets;
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
        int userNamesLength = parseIntField(DataFormatConstants.STRING_SIZE_LENGTH);
        message.setUserNamesLength(userNamesLength);
        LOGGER.debug("UserNames length: {}", userNamesLength);
        int oldPointer = getPointer();
        int bytesToRead = message.getUserNamesLength().getValue();
        while (getPointer() - oldPointer < bytesToRead) {
            int usernameLength = parseIntField(DataFormatConstants.STRING_SIZE_LENGTH);
            LOGGER.debug("UserName length: {}", usernameLength);
            String username = parseByteString(usernameLength, StandardCharsets.UTF_8);
            message.addUserName(username);
            LOGGER.debug("UserName: {}", () -> backslashEscapeString(username));
        }
    }

    private void parseGroupNames() {
        int groupNamesLength = parseIntField(DataFormatConstants.STRING_SIZE_LENGTH);
        message.setGroupNamesLength(groupNamesLength);
        LOGGER.debug("GroupNames length: {}", groupNamesLength);
        int oldPointer = getPointer();
        int bytesToRead = message.getGroupNamesLength().getValue();
        while (getPointer() - oldPointer < bytesToRead) {
            int usernameLength = parseIntField(DataFormatConstants.STRING_SIZE_LENGTH);
            LOGGER.debug("GroupName length: {}", usernameLength);
            String groupName = parseByteString(usernameLength, StandardCharsets.UTF_8);
            message.addGroupName(groupName);
            LOGGER.debug("GroupName: {}", () -> backslashEscapeString(groupName));
        }
    }

    @Override
    protected void parseResponseSpecificContents() {
        parseUserNames();
        parseGroupNames();
    }
}
