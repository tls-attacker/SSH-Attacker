/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.parser.extended_response;

import de.rub.nds.sshattacker.core.data.sftp.message.extended_response.SftpResponseLimitsMessage;
import de.rub.nds.sshattacker.core.data.sftp.parser.response.SftpResponseMessageParser;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class SftpResponseLimitsMessageParser
        extends SftpResponseMessageParser<SftpResponseLimitsMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public SftpResponseLimitsMessageParser(byte[] array) {
        super(array);
    }

    public SftpResponseLimitsMessageParser(byte[] array, int startPosition) {
        super(array, startPosition);
    }

    @Override
    public SftpResponseLimitsMessage createMessage() {
        return new SftpResponseLimitsMessage();
    }

    @Override
    protected void parseResponseSpecificContents() {
        long maximumPacketLength = parseLongField();
        message.setMaximumPacketLength(maximumPacketLength);
        LOGGER.debug("MaximumPacketLength: {}", maximumPacketLength);

        long maximumReadLength = parseLongField();
        message.setMaximumReadLength(maximumReadLength);
        LOGGER.debug("MaximumReadLength: {}", maximumReadLength);

        long maximumWriteLength = parseLongField();
        message.setMaximumWriteLength(maximumWriteLength);
        LOGGER.debug("MaximumWriteLength: {}", maximumWriteLength);

        long maximumOpenHandles = parseLongField();
        message.setMaximumOpenHandles(maximumOpenHandles);
        LOGGER.debug("MaximumOpenHandles: {}", maximumOpenHandles);
    }
}
