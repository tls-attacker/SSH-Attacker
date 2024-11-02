/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.serializer.extended_response;

import de.rub.nds.sshattacker.core.constants.DataFormatConstants;
import de.rub.nds.sshattacker.core.data.sftp.message.extended_response.SftpResponseLimitsMessage;
import de.rub.nds.sshattacker.core.data.sftp.serializer.response.SftpResponseMessageSerializer;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class SftpResponseLimitsMessageSerializer
        extends SftpResponseMessageSerializer<SftpResponseLimitsMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public SftpResponseLimitsMessageSerializer(SftpResponseLimitsMessage message) {
        super(message);
    }

    @Override
    protected void serializeResponseSpecificContents() {
        LOGGER.debug("MaximumPacketLength: {}", message.getMaximumPacketLength().getValue());
        appendLong(message.getMaximumPacketLength().getValue(), DataFormatConstants.UINT64_SIZE);

        LOGGER.debug("MaximumReadLength: {}", message.getMaximumReadLength().getValue());
        appendLong(message.getMaximumReadLength().getValue(), DataFormatConstants.UINT64_SIZE);

        LOGGER.debug("MaximumWriteLength: {}", message.getMaximumWriteLength().getValue());
        appendLong(message.getMaximumWriteLength().getValue(), DataFormatConstants.UINT64_SIZE);

        LOGGER.debug("MaximumOpenHandles: {}", message.getMaximumOpenHandles().getValue());
        appendLong(message.getMaximumOpenHandles().getValue(), DataFormatConstants.UINT64_SIZE);
    }
}
