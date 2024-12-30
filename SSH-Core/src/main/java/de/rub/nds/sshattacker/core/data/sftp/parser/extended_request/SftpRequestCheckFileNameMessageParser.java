/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.parser.extended_request;

import static de.rub.nds.modifiablevariable.util.StringUtil.backslashEscapeString;

import de.rub.nds.sshattacker.core.data.sftp.message.extended_request.SftpRequestCheckFileNameMessage;
import java.nio.charset.StandardCharsets;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class SftpRequestCheckFileNameMessageParser
        extends SftpRequestExtendedWithPathMessageParser<SftpRequestCheckFileNameMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public SftpRequestCheckFileNameMessageParser(byte[] array) {
        super(array);
    }

    public SftpRequestCheckFileNameMessageParser(byte[] array, int startPosition) {
        super(array, startPosition);
    }

    @Override
    protected SftpRequestCheckFileNameMessage createMessage() {
        return new SftpRequestCheckFileNameMessage();
    }

    private void parseHashAlgorithms() {
        int hashAlgorithmsLength = parseIntField();
        message.setHashAlgorithmsLength(hashAlgorithmsLength);
        LOGGER.debug("HashAlgorithms length: {}", hashAlgorithmsLength);
        String hashAlgorithms = parseByteString(hashAlgorithmsLength, StandardCharsets.US_ASCII);
        message.setHashAlgorithms(hashAlgorithms);
        LOGGER.debug("HashAlgorithms: {}", () -> backslashEscapeString(hashAlgorithms));
    }

    private void parseStartOffset() {
        long startOffset = parseLongField();
        message.setStartOffset(startOffset);
        LOGGER.debug("StartOffset: {}", startOffset);
    }

    private void parseLength() {
        long length = parseLongField();
        message.setLength(length);
        LOGGER.debug("Length: {}", length);
    }

    private void parseBlockSize() {
        int blockSize = parseIntField();
        message.setBlockSize(blockSize);
        LOGGER.debug("BlockSize: {}", blockSize);
    }

    @Override
    protected void parseRequestExtendedWithPathSpecificContents() {
        parseHashAlgorithms();
        parseStartOffset();
        parseLength();
        parseBlockSize();
    }
}
