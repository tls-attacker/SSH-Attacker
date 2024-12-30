/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.serializer.extended_response;

import de.rub.nds.sshattacker.core.data.sftp.message.extended_response.SftpResponseStatVfsMessage;
import de.rub.nds.sshattacker.core.data.sftp.serializer.response.SftpResponseMessageSerializer;
import de.rub.nds.sshattacker.core.protocol.common.SerializerStream;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class SftpResponseStatVfsMessageSerializer
        extends SftpResponseMessageSerializer<SftpResponseStatVfsMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    @Override
    protected void serializeResponseSpecificContents(
            SftpResponseStatVfsMessage object, SerializerStream output) {
        Long blockSize = object.getBlockSize().getValue();
        LOGGER.debug("BlockSize: {}", blockSize);
        output.appendLong(blockSize);

        Long fundamentalBlockSize = object.getFundamentalBlockSize().getValue();
        LOGGER.debug("FundamentalBlockSize: {}", fundamentalBlockSize);
        output.appendLong(fundamentalBlockSize);

        Long countBlocks = object.getCountBlocks().getValue();
        LOGGER.debug("CountBlocks: {}", countBlocks);
        output.appendLong(countBlocks);

        Long freeBlocks = object.getFreeBlocks().getValue();
        LOGGER.debug("FreeBlocks: {}", freeBlocks);
        output.appendLong(freeBlocks);

        Long freeBlocksNonRoot = object.getFreeBlocksNonRoot().getValue();
        LOGGER.debug("FreeBlocksNonRoot: {}", freeBlocksNonRoot);
        output.appendLong(freeBlocksNonRoot);

        Long fileInodes = object.getFileInodes().getValue();
        LOGGER.debug("FileInodes: {}", fileInodes);
        output.appendLong(fileInodes);

        Long freeInodes = object.getFreeInodes().getValue();
        LOGGER.debug("FreeInodes: {}", freeInodes);
        output.appendLong(freeInodes);

        Long freeInodesNonRoot = object.getFreeInodesNonRoot().getValue();
        LOGGER.debug("FreeInodesNonRoot: {}", freeInodesNonRoot);
        output.appendLong(freeInodesNonRoot);

        Long systemId = object.getSystemId().getValue();
        LOGGER.debug("SystemId: {}", systemId);
        output.appendLong(systemId);

        Long flags = object.getFlags().getValue();
        LOGGER.debug("Flags: {}", flags);
        output.appendLong(flags);

        Long maximumFilenameLength = object.getMaximumFilenameLength().getValue();
        LOGGER.debug("MaximumFilenameLength: {}", maximumFilenameLength);
        output.appendLong(maximumFilenameLength);
    }
}
