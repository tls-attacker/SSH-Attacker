/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.parser.extended_request;

import static de.rub.nds.modifiablevariable.util.StringUtil.backslashEscapeString;

import de.rub.nds.sshattacker.core.constants.DataFormatConstants;
import de.rub.nds.sshattacker.core.data.sftp.message.extended_request.SftpRequestCheckFileHandleMessage;
import java.nio.charset.StandardCharsets;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class SftpRequestCheckFileHandleMessageParser
        extends SftpRequestExtendedWithHandleMessageParser<SftpRequestCheckFileHandleMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public SftpRequestCheckFileHandleMessageParser(byte[] array) {
        super(array);
    }

    public SftpRequestCheckFileHandleMessageParser(byte[] array, int startPosition) {
        super(array, startPosition);
    }

    @Override
    protected SftpRequestCheckFileHandleMessage createMessage() {
        return new SftpRequestCheckFileHandleMessage();
    }

    private void parseHashAlgorithms() {
        int hashAlgorithmsLength = parseIntField(DataFormatConstants.STRING_SIZE_LENGTH);
        message.setHashAlgorithmsLength(hashAlgorithmsLength);
        LOGGER.debug("HashAlgorithms length: {}", hashAlgorithmsLength);
        String hashAlgorithms = parseByteString(hashAlgorithmsLength, StandardCharsets.US_ASCII);
        message.setHashAlgorithms(hashAlgorithms);
        LOGGER.debug("HashAlgorithms: {}", () -> backslashEscapeString(hashAlgorithms));
    }

    private void parseStartOffset() {
        long startOffset = parseLongField(DataFormatConstants.UINT64_SIZE);
        message.setStartOffset(startOffset);
        LOGGER.debug("StartOffset: {}", startOffset);
    }

    private void parseLength() {
        long length = parseLongField(DataFormatConstants.UINT64_SIZE);
        message.setLength(length);
        LOGGER.debug("Length: {}", length);
    }

    private void parseBlockSize() {
        int blockSize = parseIntField(DataFormatConstants.UINT32_SIZE);
        message.setBlockSize(blockSize);
        LOGGER.debug("BlockSize: {}", blockSize);
    }

    @Override
    protected void parseRequestExtendedWithHandleSpecificContents() {
        parseHashAlgorithms();
        parseStartOffset();
        parseLength();
        parseBlockSize();
    }
}
