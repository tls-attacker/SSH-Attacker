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
import de.rub.nds.sshattacker.core.data.packet.AbstractDataPacket;
import de.rub.nds.sshattacker.core.data.sftp.common.message.SftpUnknownMessage;
import de.rub.nds.sshattacker.core.data.sftp.common.message.extended_request.SftpRequestExtendedMessage;
import de.rub.nds.sshattacker.core.data.sftp.common.message.extended_request.SftpRequestUnknownMessage;
import de.rub.nds.sshattacker.core.data.sftp.common.message.extended_response.SftpResponseUnknownMessage;
import de.rub.nds.sshattacker.core.data.sftp.common.message.request.SftpRequestMessage;
import de.rub.nds.sshattacker.core.data.sftp.common.parser.SftpInitMessageParser;
import de.rub.nds.sshattacker.core.data.sftp.common.parser.SftpUnknownMessageParser;
import de.rub.nds.sshattacker.core.data.sftp.common.parser.SftpVersionMessageParser;
import de.rub.nds.sshattacker.core.data.sftp.common.parser.extended_request.*;
import de.rub.nds.sshattacker.core.data.sftp.common.parser.extended_response.*;
import de.rub.nds.sshattacker.core.data.sftp.common.parser.request.*;
import de.rub.nds.sshattacker.core.data.sftp.common.parser.response.*;
import de.rub.nds.sshattacker.core.data.sftp.v4.parser.SftpV4InitMessageParser;
import de.rub.nds.sshattacker.core.data.sftp.v4.parser.request.*;
import de.rub.nds.sshattacker.core.data.sftp.v4.parser.response.SftpV4ResponseAttributesMessageParser;
import de.rub.nds.sshattacker.core.data.sftp.v4.parser.response.SftpV4ResponseNameMessageParser;
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
        message.setPacketType(parseByteField());
    }

    public static SftpMessage<?> delegateParsing(AbstractDataPacket packet, SshContext context) {
        int sftpVersion =
                context.getSftpNegotiatedVersion()
                        .orElse(context.getConfig().getSftpNegotiatedVersion());
        if (sftpVersion >= 4) {
            return delegateParsingV4(packet, context);
        } else {
            return delegateParsingV3(packet, context);
        }
    }

    public static SftpMessage<?> delegateParsingV3(AbstractDataPacket packet, SshContext context) {
        byte[] raw = packet.getPayload().getValue();
        if (raw.length == 0) {
            return new SftpUnknownMessage();
        }
        try {
            return switch (SftpPacketTypeConstant.fromId(raw[0])) {
                case SSH_FXP_INIT -> new SftpInitMessageParser(raw).parse();
                case SSH_FXP_VERSION -> new SftpVersionMessageParser(raw).parse();
                case SSH_FXP_OPEN -> new SftpRequestOpenMessageParser(raw).parse();
                case SSH_FXP_CLOSE -> new SftpRequestCloseMessageParser(raw).parse();
                case SSH_FXP_READ -> new SftpRequestReadMessageParser(raw).parse();
                case SSH_FXP_WRITE -> new SftpRequestWriteMessageParser(raw).parse();
                case SSH_FXP_LSTAT -> new SftpRequestLinkStatMessageParser(raw).parse();
                case SSH_FXP_FSTAT -> new SftpRequestFileStatMessageParser(raw).parse();
                case SSH_FXP_SETSTAT -> new SftpRequestSetStatMessageParser(raw).parse();
                case SSH_FXP_FSETSTAT -> new SftpRequestFileSetStatMessageParser(raw).parse();
                case SSH_FXP_OPENDIR -> new SftpRequestOpenDirMessageParser(raw).parse();
                case SSH_FXP_READDIR -> new SftpRequestReadDirMessageParser(raw).parse();
                case SSH_FXP_REMOVE -> new SftpRequestRemoveMessageParser(raw).parse();
                case SSH_FXP_MKDIR -> new SftpRequestMakeDirMessageParser(raw).parse();
                case SSH_FXP_RMDIR -> new SftpRequestRemoveDirMessageParser(raw).parse();
                case SSH_FXP_REALPATH -> new SftpRequestRealPathMessageParser(raw).parse();
                case SSH_FXP_STAT -> new SftpRequestStatMessageParser(raw).parse();
                case SSH_FXP_RENAME -> new SftpRequestRenameMessageParser(raw).parse();
                case SSH_FXP_READLINK -> new SftpRequestReadLinkMessageParser(raw).parse();
                case SSH_FXP_SYMLINK -> new SftpRequestSymbolicLinkMessageParser(raw).parse();
                case SSH_FXP_STATUS -> new SftpResponseStatusMessageParser(raw).parse();
                case SSH_FXP_HANDLE -> new SftpResponseHandleMessageParser(raw).parse();
                case SSH_FXP_DATA -> new SftpResponseDataMessageParser(raw).parse();
                case SSH_FXP_NAME -> new SftpResponseNameMessageParser(raw).parse();
                case SSH_FXP_ATTRS -> new SftpResponseAttributesMessageParser(raw).parse();
                case SSH_FXP_EXTENDED -> handleExtendedRequestMessageParsing(raw, context);
                case SSH_FXP_EXTENDED_REPLY -> handleExtendedResponseMessageParsing(raw, context);
                default -> {
                    LOGGER.debug(
                            "Received unimplemented SFTP Message {} ({})",
                            SftpPacketTypeConstant.getNameById(raw[0]),
                            raw[0]);
                    yield new SftpUnknownMessageParser(raw).parse();
                }
            };
        } catch (ParserException e) {
            LOGGER.debug("Error while Parsing, now parsing as UnknownMessage", e);
            return new SftpUnknownMessageParser(raw).parse();
        }
    }

    public static SftpMessage<?> delegateParsingV4(AbstractDataPacket packet, SshContext context) {
        byte[] raw = packet.getPayload().getValue();
        if (raw.length == 0) {
            return new SftpUnknownMessage();
        }
        try {
            return switch (SftpPacketTypeConstant.fromId(raw[0])) {
                case SSH_FXP_INIT -> new SftpV4InitMessageParser(raw).parse();
                case SSH_FXP_OPEN -> new SftpV4RequestOpenMessageParser(raw).parse();
                case SSH_FXP_FSTAT -> new SftpV4RequestFileStatMessageParser(raw).parse();
                case SSH_FXP_SETSTAT -> new SftpV4RequestSetStatMessageParser(raw).parse();
                case SSH_FXP_FSETSTAT -> new SftpV4RequestFileSetStatMessageParser(raw).parse();
                case SSH_FXP_MKDIR -> new SftpV4RequestMakeDirMessageParser(raw).parse();
                case SSH_FXP_STAT -> new SftpV4RequestStatMessageParser(raw).parse();
                case SSH_FXP_NAME -> new SftpV4ResponseNameMessageParser(raw).parse();
                case SSH_FXP_ATTRS -> new SftpV4ResponseAttributesMessageParser(raw).parse();
                default -> delegateParsingV3(packet, context);
            };
        } catch (ParserException e) {
            LOGGER.debug("Error while Parsing, now parsing as UnknownMessage", e);
            return new SftpUnknownMessageParser(raw).parse();
        }
    }

    public static SftpMessage<?> handleExtendedRequestMessageParsing(
            byte[] raw, SshContext context) {
        SftpRequestUnknownMessage message = new SftpRequestUnknownMessageParser(raw).parse();
        String extendedRequestTypeString = message.getExtendedRequestName().getValue();
        SftpExtension extendedRequestType = SftpExtension.fromName(extendedRequestTypeString);
        return switch (extendedRequestType) {
            case VENDOR_ID -> new SftpRequestVendorIdMessageParser(raw).parse();
            case CHECK_FILE_HANDLE -> new SftpRequestCheckFileHandleMessageParser(raw).parse();
            case CHECK_FILE_NAME -> new SftpRequestCheckFileNameMessageParser(raw).parse();
            case SPACE_AVAILABLE -> new SftpRequestSpaceAvailableMessageParser(raw).parse();
            case HOME_DIRECTORY -> new SftpRequestHomeDirectoryMessageParser(raw).parse();
            case COPY_FILE -> new SftpRequestCopyFileMessageParser(raw).parse();
            case COPY_DATA -> new SftpRequestCopyDataMessageParser(raw).parse();
            case GET_TEMP_FOLDER -> new SftpRequestGetTempFolderMessageParser(raw).parse();
            case MAKE_TEMP_FOLDER -> new SftpRequestMakeTempFolderMessageParser(raw).parse();
            // SFTP v4
            case TEXT_SEEK -> new SftpRequestTextSeekMessageParser(raw).parse();
            // vendor specific
            case POSIX_RENAME_OPENSSH_COM -> new SftpRequestPosixRenameMessageParser(raw).parse();
            case STAT_VFS_OPENSSH_COM -> new SftpRequestStatVfsMessageParser(raw).parse();
            case F_STAT_VFS_OPENSSH_COM -> new SftpRequestFileStatVfsMessageParser(raw).parse();
            case HARDLINK_OPENSSH_COM -> new SftpRequestHardlinkMessageParser(raw).parse();
            case F_SYNC_OPENSSH_COM -> new SftpRequestFileSyncMessageParser(raw).parse();
            case L_SET_STAT -> new SftpRequestLinkSetStatMessageParser(raw).parse();
            case LIMITS -> new SftpRequestLimitsMessageParser(raw).parse();
            case EXPAND_PATH -> new SftpRequestExpandPathMessageParser(raw).parse();
            case USERS_GROUPS_BY_ID -> new SftpRequestUsersGroupsByIdMessageParser(raw).parse();
            default -> {
                LOGGER.debug(
                        "Received unimplemented extended request message type: {}",
                        extendedRequestTypeString);
                yield message;
            }
        };
    }

    public static SftpMessage<?> handleExtendedResponseMessageParsing(
            byte[] raw, SshContext context) {
        SftpResponseUnknownMessage message = new SftpResponseUnknownMessageParser(raw).parse();
        SftpRequestMessage<?> relatedRequest =
                context.getSftpManager().removeRequestById(message.getRequestId().getValue());

        if (!(relatedRequest instanceof SftpRequestExtendedMessage<?> relatedExtendedRequest)) {
            return message;
        }

        SftpExtension extendedResponseType =
                SftpExtension.fromName(relatedExtendedRequest.getExtendedRequestName().getValue());
        return switch (extendedResponseType) {
            // SFTP
            case CHECK_FILE, CHECK_FILE_HANDLE, CHECK_FILE_NAME ->
                    new SftpResponseCheckFileMessageParser(raw).parse();
            case SPACE_AVAILABLE -> new SftpResponseSpaceAvailableMessageParser(raw).parse();
            // Vendor extensions
            case STAT_VFS_OPENSSH_COM, F_STAT_VFS_OPENSSH_COM ->
                    new SftpResponseStatVfsMessageParser(raw).parse();
            case LIMITS -> new SftpResponseLimitsMessageParser(raw).parse();
            case USERS_GROUPS_BY_ID -> new SftpResponseUsersGroupsByIdMessageParser(raw).parse();
            default -> {
                LOGGER.debug(
                        "Received unimplemented extended response message type: {}",
                        extendedResponseType);
                yield message;
            }
        };
    }
}
