/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp;

import de.rub.nds.sshattacker.core.constants.SftpExtension;
import de.rub.nds.sshattacker.core.constants.SftpPacketTypeConstant;
import de.rub.nds.sshattacker.core.constants.SshMessageConstants;
import de.rub.nds.sshattacker.core.data.packet.AbstractDataPacket;
import de.rub.nds.sshattacker.core.data.sftp.message.extended_request.SftpRequestUnknownMessage;
import de.rub.nds.sshattacker.core.data.sftp.parser.*;
import de.rub.nds.sshattacker.core.data.sftp.parser.extended_request.*;
import de.rub.nds.sshattacker.core.data.sftp.parser.request.*;
import de.rub.nds.sshattacker.core.data.sftp.parser.response.*;
import de.rub.nds.sshattacker.core.exceptions.ParserException;
import de.rub.nds.sshattacker.core.protocol.common.ProtocolMessageParser;
import de.rub.nds.sshattacker.core.state.SshContext;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public abstract class SftpMessageParser<T extends SftpMessage<T>> extends ProtocolMessageParser<T> {

    private static final Logger LOGGER = LogManager.getLogger();

    protected SftpMessageParser(byte[] array) {
        super(array);
    }

    protected SftpMessageParser(byte[] array, int startPosition) {
        super(array, startPosition);
    }

    @Override
    protected final void parseProtocolMessageContents() {
        parsePacketType();
        parseMessageSpecificContents();
    }

    protected abstract void parseMessageSpecificContents();

    private void parsePacketType() {
        message.setPacketType(parseByteField(SshMessageConstants.MESSAGE_ID_LENGTH));
    }

    public static SftpMessage<?> delegateParsing(AbstractDataPacket packet, SshContext context) {
        byte[] raw = packet.getPayload().getValue();

        try {
            switch (SftpPacketTypeConstant.fromId(raw[0])) {
                case SSH_FXP_INIT:
                    return new SftpInitMessageParser(raw).parse();
                case SSH_FXP_VERSION:
                    return new SftpVersionMessageParser(raw).parse();
                case SSH_FXP_OPEN:
                    return new SftpRequestOpenMessageParser(raw).parse();
                case SSH_FXP_CLOSE:
                    return new SftpRequestCloseMessageParser(raw).parse();
                case SSH_FXP_READ:
                    return new SftpRequestReadMessageParser(raw).parse();
                case SSH_FXP_WRITE:
                    return new SftpRequestWriteMessageParser(raw).parse();
                case SSH_FXP_LSTAT:
                    return new SftpRequestLinkStatMessageParser(raw).parse();
                case SSH_FXP_FSTAT:
                    return new SftpRequestFileStatMessageParser(raw).parse();
                case SSH_FXP_SETSTAT:
                    return new SftpRequestSetStatMessageParser(raw).parse();
                case SSH_FXP_FSETSTAT:
                    return new SftpRequestFileSetStatMessageParser(raw).parse();
                case SSH_FXP_OPENDIR:
                    return new SftpRequestOpenDirMessageParser(raw).parse();
                case SSH_FXP_READDIR:
                    return new SftpRequestReadDirMessageParser(raw).parse();
                case SSH_FXP_REMOVE:
                    return new SftpRequestRemoveMessageParser(raw).parse();
                case SSH_FXP_MKDIR:
                    return new SftpRequestMakeDirMessageParser(raw).parse();
                case SSH_FXP_RMDIR:
                    return new SftpRequestRemoveDirMessageParser(raw).parse();
                case SSH_FXP_REALPATH:
                    return new SftpRequestRealPathMessageParser(raw).parse();
                case SSH_FXP_STAT:
                    return new SftpRequestStatMessageParser(raw).parse();
                case SSH_FXP_RENAME:
                    return new SftpRequestRenameMessageParser(raw).parse();
                case SSH_FXP_READLINK:
                    return new SftpRequestReadLinkMessageParser(raw).parse();
                case SSH_FXP_SYMLINK:
                    return new SftpRequestSymbolicLinkMessageParser(raw).parse();
                case SSH_FXP_STATUS:
                    return new SftpResponseStatusMessageParser(raw).parse();
                case SSH_FXP_HANDLE:
                    return new SftpResponseHandleMessageParser(raw).parse();
                case SSH_FXP_DATA:
                    return new SftpResponseDataMessageParser(raw).parse();
                case SSH_FXP_NAME:
                    return new SftpResponseNameMessageParser(raw).parse();
                case SSH_FXP_ATTRS:
                    return new SftpResponseAttributesMessageParser(raw).parse();
                case SSH_FXP_EXTENDED:
                    return handleExtendedRequestMessageParsing(raw);
                default:
                    LOGGER.debug(
                            "Received unimplemented SFTP Message {} ({})",
                            SftpPacketTypeConstant.getNameById(raw[0]),
                            raw[0]);
                    return new SftpUnknownMessageParser(raw).parse();
            }
        } catch (ParserException e) {
            LOGGER.debug("Error while Parsing, now parsing as UnknownMessage", e);
            return new SftpUnknownMessageParser(raw).parse();
        }
    }

    public static SftpMessage<?> handleExtendedRequestMessageParsing(byte[] raw) {
        SftpRequestUnknownMessage message = new SftpRequestUnknownMessageParser(raw).parse();
        String extendedRequestTypeString = message.getExtendedRequestName().getValue();
        SftpExtension extendedRequestType = SftpExtension.fromName(extendedRequestTypeString);
        switch (extendedRequestType) {
            case VENDOR_ID:
                return new SftpRequestVendorIdMessageParser(raw).parse();
            case CHECK_FILE_HANDLE:
                return new SftpRequestCheckFileHandleMessageParser(raw).parse();
            case CHECK_FILE_NAME:
                return new SftpRequestCheckFileNameMessageParser(raw).parse();
            case SPACE_AVAILABLE:
                return new SftpRequestSpaceAvailableMessageParser(raw).parse();
            case HOME_DIRECTORY:
                return new SftpRequestHomeDirectoryMessageParser(raw).parse();
            case COPY_FILE:
                return new SftpRequestCopyFileMessageParser(raw).parse();
            case COPY_DATA:
                return new SftpRequestCopyDataMessageParser(raw).parse();
            case GET_TEMP_FOLDER:
                return new SftpRequestGetTempFolderMessageParser(raw).parse();
            case MAKE_TEMP_FOLDER:
                return new SftpRequestMakeTempFolderMessageParser(raw).parse();
                // vendor specific
            case POSIX_RENAME_OPENSSH_COM:
                return new SftpRequestPosixRenameMessageParser(raw).parse();
            case STAT_VFS_OPENSSH_COM:
                return new SftpRequestStatVfsMessageParser(raw).parse();
            case F_STAT_VFS_OPENSSH_COM:
                return new SftpRequestFileStatVfsMessageParser(raw).parse();
            case HARDLINK_OPENSSH_COM:
                return new SftpRequestHardlinkMessageParser(raw).parse();
            case F_SYNC_OPENSSH_COM:
                return new SftpRequestFileSyncMessageParser(raw).parse();
            case L_SET_STAT:
                return new SftpRequestLinkSetStatMessageParser(raw).parse();
            case LIMITS:
                return new SftpRequestLimitsMessageParser(raw).parse();
            case EXPAND_PATH:
                return new SftpRequestExpandPathMessageParser(raw).parse();
            case USERS_GROUPS_BY_ID:
                return new SftpRequestUsersGroupsByIdMessageParser(raw).parse();
            default:
                LOGGER.debug(
                        "Received unimplemented extended request message type: {}",
                        extendedRequestTypeString);
                return message;
        }
    }
}
