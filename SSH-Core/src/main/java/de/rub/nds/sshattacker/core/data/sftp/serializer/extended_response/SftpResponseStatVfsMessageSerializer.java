/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.serializer.extended_response;

import de.rub.nds.sshattacker.core.constants.DataFormatConstants;
import de.rub.nds.sshattacker.core.data.sftp.message.extended_response.SftpResponseStatVfsMessage;
import de.rub.nds.sshattacker.core.data.sftp.serializer.response.SftpResponseMessageSerializer;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class SftpResponseStatVfsMessageSerializer
        extends SftpResponseMessageSerializer<SftpResponseStatVfsMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public SftpResponseStatVfsMessageSerializer(SftpResponseStatVfsMessage message) {
        super(message);
    }

    @Override
    protected void serializeResponseSpecificContents() {
        LOGGER.debug("BlockSize: {}", message.getBlockSize().getValue());
        appendLong(message.getBlockSize().getValue(), DataFormatConstants.UINT64_SIZE);

        LOGGER.debug("FundamentalBlockSize: {}", message.getFundamentalBlockSize().getValue());
        appendLong(message.getFundamentalBlockSize().getValue(), DataFormatConstants.UINT64_SIZE);

        LOGGER.debug("CountBlocks: {}", message.getCountBlocks().getValue());
        appendLong(message.getCountBlocks().getValue(), DataFormatConstants.UINT64_SIZE);

        LOGGER.debug("FreeBlocks: {}", message.getFreeBlocks().getValue());
        appendLong(message.getFreeBlocks().getValue(), DataFormatConstants.UINT64_SIZE);

        LOGGER.debug("FreeBlocksNonRoot: {}", message.getFreeBlocksNonRoot().getValue());
        appendLong(message.getFreeBlocksNonRoot().getValue(), DataFormatConstants.UINT64_SIZE);

        LOGGER.debug("FileInodes: {}", message.getFileInodes().getValue());
        appendLong(message.getFileInodes().getValue(), DataFormatConstants.UINT64_SIZE);

        LOGGER.debug("FreeInodes: {}", message.getFreeInodes().getValue());
        appendLong(message.getFreeInodes().getValue(), DataFormatConstants.UINT64_SIZE);

        LOGGER.debug("FreeInodesNonRoot: {}", message.getFreeInodesNonRoot().getValue());
        appendLong(message.getFreeInodesNonRoot().getValue(), DataFormatConstants.UINT64_SIZE);

        LOGGER.debug("SystemId: {}", message.getSystemId().getValue());
        appendLong(message.getSystemId().getValue(), DataFormatConstants.UINT64_SIZE);

        LOGGER.debug("Flags: {}", message.getFlags().getValue());
        appendLong(message.getFlags().getValue(), DataFormatConstants.UINT64_SIZE);

        LOGGER.debug("MaximumFilenameLength: {}", message.getMaximumFilenameLength().getValue());
        appendLong(message.getMaximumFilenameLength().getValue(), DataFormatConstants.UINT64_SIZE);
    }
}
