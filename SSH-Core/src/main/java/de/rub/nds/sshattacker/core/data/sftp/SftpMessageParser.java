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
import de.rub.nds.sshattacker.core.data.sftp.parser.SftpInitMessageParser;
import de.rub.nds.sshattacker.core.data.sftp.parser.SftpUnknownMessageParser;
import de.rub.nds.sshattacker.core.data.sftp.parser.SftpVersionMessageParser;
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
