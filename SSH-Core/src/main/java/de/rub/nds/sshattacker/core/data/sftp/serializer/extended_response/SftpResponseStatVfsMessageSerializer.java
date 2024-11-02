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
        Long blockSize = message.getBlockSize().getValue();
        LOGGER.debug("BlockSize: {}", blockSize);
        appendLong(blockSize, DataFormatConstants.UINT64_SIZE);

        Long fundamentalBlockSize = message.getFundamentalBlockSize().getValue();
        LOGGER.debug("FundamentalBlockSize: {}", fundamentalBlockSize);
        appendLong(fundamentalBlockSize, DataFormatConstants.UINT64_SIZE);

        Long countBlocks = message.getCountBlocks().getValue();
        LOGGER.debug("CountBlocks: {}", countBlocks);
        appendLong(countBlocks, DataFormatConstants.UINT64_SIZE);

        Long freeBlocks = message.getFreeBlocks().getValue();
        LOGGER.debug("FreeBlocks: {}", freeBlocks);
        appendLong(freeBlocks, DataFormatConstants.UINT64_SIZE);

        Long freeBlocksNonRoot = message.getFreeBlocksNonRoot().getValue();
        LOGGER.debug("FreeBlocksNonRoot: {}", freeBlocksNonRoot);
        appendLong(freeBlocksNonRoot, DataFormatConstants.UINT64_SIZE);

        Long fileInodes = message.getFileInodes().getValue();
        LOGGER.debug("FileInodes: {}", fileInodes);
        appendLong(fileInodes, DataFormatConstants.UINT64_SIZE);

        Long freeInodes = message.getFreeInodes().getValue();
        LOGGER.debug("FreeInodes: {}", freeInodes);
        appendLong(freeInodes, DataFormatConstants.UINT64_SIZE);

        Long freeInodesNonRoot = message.getFreeInodesNonRoot().getValue();
        LOGGER.debug("FreeInodesNonRoot: {}", freeInodesNonRoot);
        appendLong(freeInodesNonRoot, DataFormatConstants.UINT64_SIZE);

        Long systemId = message.getSystemId().getValue();
        LOGGER.debug("SystemId: {}", systemId);
        appendLong(systemId, DataFormatConstants.UINT64_SIZE);

        Long flags = message.getFlags().getValue();
        LOGGER.debug("Flags: {}", flags);
        appendLong(flags, DataFormatConstants.UINT64_SIZE);

        Long maximumFilenameLength = message.getMaximumFilenameLength().getValue();
        LOGGER.debug("MaximumFilenameLength: {}", maximumFilenameLength);
        appendLong(maximumFilenameLength, DataFormatConstants.UINT64_SIZE);
    }
}
