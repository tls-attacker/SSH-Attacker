/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.parser.extended_response;

import de.rub.nds.sshattacker.core.constants.DataFormatConstants;
import de.rub.nds.sshattacker.core.data.sftp.message.extended_response.SftpResponseStatVfsMessage;
import de.rub.nds.sshattacker.core.data.sftp.parser.response.SftpResponseMessageParser;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class SftpResponseStatVfsMessageParser
        extends SftpResponseMessageParser<SftpResponseStatVfsMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public SftpResponseStatVfsMessageParser(byte[] array) {
        super(array);
    }

    public SftpResponseStatVfsMessageParser(byte[] array, int startPosition) {
        super(array, startPosition);
    }

    @Override
    public SftpResponseStatVfsMessage createMessage() {
        return new SftpResponseStatVfsMessage();
    }

    private void parseBlockSize() {
        long blockSize = parseLongField(DataFormatConstants.UINT64_SIZE);
        message.setBlockSize(blockSize);
        LOGGER.debug("BlockSize: {}", blockSize);
    }

    private void parseFundamentalBlockSize() {
        long fundamentalBlockSize = parseLongField(DataFormatConstants.UINT64_SIZE);
        message.setFundamentalBlockSize(fundamentalBlockSize);
        LOGGER.debug("FundamentalBlockSize: {}", fundamentalBlockSize);
    }

    private void parseCountBlocks() {
        long countBlocks = parseLongField(DataFormatConstants.UINT64_SIZE);
        message.setCountBlocks(countBlocks);
        LOGGER.debug("CountBlocks: {}", countBlocks);
    }

    private void parseFreeBlocks() {
        long freeBlocks = parseLongField(DataFormatConstants.UINT64_SIZE);
        message.setFreeBlocks(freeBlocks);
        LOGGER.debug("FreeBlocks: {}", freeBlocks);
    }

    private void parseFreeBlocksNonRoot() {
        long freeBlocksNonRoot = parseLongField(DataFormatConstants.UINT64_SIZE);
        message.setFreeBlocksNonRoot(freeBlocksNonRoot);
        LOGGER.debug("FreeBlocksNonRoot: {}", freeBlocksNonRoot);
    }

    private void parseFileInodes() {
        long fileInodes = parseLongField(DataFormatConstants.UINT64_SIZE);
        message.setFileInodes(fileInodes);
        LOGGER.debug("FileInodes: {}", fileInodes);
    }

    private void parseFreeInodes() {
        long freeInodes = parseLongField(DataFormatConstants.UINT64_SIZE);
        message.setFreeInodes(freeInodes);
        LOGGER.debug("FreeInodes: {}", freeInodes);
    }

    private void parseFreeInodesNonRoot() {
        long freeInodesNonRoot = parseLongField(DataFormatConstants.UINT64_SIZE);
        message.setFreeInodesNonRoot(freeInodesNonRoot);
        LOGGER.debug("FreeInodesNonRoot: {}", freeInodesNonRoot);
    }

    private void parseSystemId() {
        long systemId = parseLongField(DataFormatConstants.UINT64_SIZE);
        message.setSystemId(systemId);
        LOGGER.debug("SystemId: {}", systemId);
    }

    private void parseFlags() {
        long flags = parseLongField(DataFormatConstants.UINT64_SIZE);
        message.setFlags(flags);
        LOGGER.debug("Flags: {}", flags);
    }

    private void parseMaximumFilenameLength() {
        long maximumFilenameLength = parseLongField(DataFormatConstants.UINT64_SIZE);
        message.setMaximumFilenameLength(maximumFilenameLength);
        LOGGER.debug("MaximumFilenameLength: {}", maximumFilenameLength);
    }

    @Override
    protected void parseResponseSpecificContents() {
        parseBlockSize();
        parseFundamentalBlockSize();
        parseCountBlocks();
        parseFreeBlocks();
        parseFreeBlocksNonRoot();
        parseFileInodes();
        parseFreeInodes();
        parseFreeInodesNonRoot();
        parseSystemId();
        parseFlags();
        parseMaximumFilenameLength();
    }
}
