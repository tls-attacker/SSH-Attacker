/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp;

import de.rub.nds.sshattacker.core.constants.SftpPacketTypeConstant;
import de.rub.nds.sshattacker.core.constants.SshMessageConstants;
import de.rub.nds.sshattacker.core.data.packet.AbstractDataPacket;
import de.rub.nds.sshattacker.core.data.sftp.parser.*;
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
}
