/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.parser.extended_response;

import de.rub.nds.sshattacker.core.constants.DataFormatConstants;
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
        message.setMaximumPacketLength(parseLongField(DataFormatConstants.UINT64_SIZE));
        LOGGER.debug("MaximumPacketLength: {}", message.getMaximumPacketLength().getValue());

        message.setMaximumReadLength(parseLongField(DataFormatConstants.UINT64_SIZE));
        LOGGER.debug("MaximumReadLength: {}", message.getMaximumReadLength().getValue());

        message.setMaximumWriteLength(parseLongField(DataFormatConstants.UINT64_SIZE));
        LOGGER.debug("MaximumWriteLength: {}", message.getMaximumWriteLength().getValue());

        message.setMaximumOpenHandles(parseLongField(DataFormatConstants.UINT64_SIZE));
        LOGGER.debug("MaximumOpenHandles: {}", message.getMaximumOpenHandles().getValue());
    }
}
