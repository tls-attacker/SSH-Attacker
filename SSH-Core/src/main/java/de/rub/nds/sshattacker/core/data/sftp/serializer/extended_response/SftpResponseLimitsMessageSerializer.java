/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.serializer.extended_response;

import de.rub.nds.sshattacker.core.data.sftp.message.extended_response.SftpResponseLimitsMessage;
import de.rub.nds.sshattacker.core.data.sftp.serializer.response.SftpResponseMessageSerializer;
import de.rub.nds.sshattacker.core.protocol.common.SerializerStream;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class SftpResponseLimitsMessageSerializer
        extends SftpResponseMessageSerializer<SftpResponseLimitsMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    @Override
    protected void serializeResponseSpecificContents(
            SftpResponseLimitsMessage object, SerializerStream output) {
        Long maximumPacketLength = object.getMaximumPacketLength().getValue();
        LOGGER.debug("MaximumPacketLength: {}", maximumPacketLength);
        output.appendLong(maximumPacketLength);

        Long maximumReadLength = object.getMaximumReadLength().getValue();
        LOGGER.debug("MaximumReadLength: {}", maximumReadLength);
        output.appendLong(maximumReadLength);

        Long maximumWriteLength = object.getMaximumWriteLength().getValue();
        LOGGER.debug("MaximumWriteLength: {}", maximumWriteLength);
        output.appendLong(maximumWriteLength);

        Long maximumOpenHandles = object.getMaximumOpenHandles().getValue();
        LOGGER.debug("MaximumOpenHandles: {}", maximumOpenHandles);
        output.appendLong(maximumOpenHandles);
    }
}
