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
        message.setBlockSize(parseLongField(DataFormatConstants.UINT64_SIZE));
        LOGGER.debug("BlockSize: {}", message.getBlockSize().getValue());
    }

    private void parseFundamentalBlockSize() {
        message.setFundamentalBlockSize(parseLongField(DataFormatConstants.UINT64_SIZE));
        LOGGER.debug("FundamentalBlockSize: {}", message.getFundamentalBlockSize().getValue());
    }

    private void parseCountBlocks() {
        message.setCountBlocks(parseLongField(DataFormatConstants.UINT64_SIZE));
        LOGGER.debug("CountBlocks: {}", message.getCountBlocks().getValue());
    }

    private void parseFreeBlocks() {
        message.setFreeBlocks(parseLongField(DataFormatConstants.UINT64_SIZE));
        LOGGER.debug("FreeBlocks: {}", message.getFreeBlocks().getValue());
    }

    private void parseFreeBlocksNonRoot() {
        message.setFreeBlocksNonRoot(parseLongField(DataFormatConstants.UINT64_SIZE));
        LOGGER.debug("FreeBlocksNonRoot: {}", message.getFreeBlocksNonRoot().getValue());
    }

    private void parseFileInodes() {
        message.setFileInodes(parseLongField(DataFormatConstants.UINT64_SIZE));
        LOGGER.debug("FileInodes: {}", message.getFileInodes().getValue());
    }

    private void parseFreeInodes() {
        message.setFreeInodes(parseLongField(DataFormatConstants.UINT64_SIZE));
        LOGGER.debug("FreeInodes: {}", message.getFreeInodes().getValue());
    }

    private void parseFreeInodesNonRoot() {
        message.setFreeInodesNonRoot(parseLongField(DataFormatConstants.UINT64_SIZE));
        LOGGER.debug("FreeInodesNonRoot: {}", message.getFreeInodesNonRoot().getValue());
    }

    private void parseSystemId() {
        message.setSystemId(parseLongField(DataFormatConstants.UINT64_SIZE));
        LOGGER.debug("SystemId: {}", message.getSystemId().getValue());
    }

    private void parseFlags() {
        message.setFlags(parseLongField(DataFormatConstants.UINT64_SIZE));
        LOGGER.debug("Flags: {}", message.getFlags().getValue());
    }

    private void parseMaximumFilenameLength() {
        message.setMaximumFilenameLength(parseLongField(DataFormatConstants.UINT64_SIZE));
        LOGGER.debug("MaximumFilenameLength: {}", message.getMaximumFilenameLength().getValue());
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
