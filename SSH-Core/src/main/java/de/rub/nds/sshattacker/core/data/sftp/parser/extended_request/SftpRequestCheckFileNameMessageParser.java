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
        message.setHashAlgorithmsLength(parseIntField(DataFormatConstants.STRING_SIZE_LENGTH));
        LOGGER.debug("HashAlgorithms length: {}", message.getHashAlgorithmsLength().getValue());
        message.setHashAlgorithms(
                parseByteString(
                        message.getHashAlgorithmsLength().getValue(), StandardCharsets.US_ASCII));
        LOGGER.debug(
                "HashAlgorithms: {}",
                () -> backslashEscapeString(message.getHashAlgorithms().getValue()));
    }

    private void parseStartOffset() {
        message.setStartOffset(parseLongField(DataFormatConstants.UINT64_SIZE));
        LOGGER.debug("StartOffset: {}", message.getStartOffset().getValue());
    }

    private void parseLength() {
        message.setLength(parseLongField(DataFormatConstants.UINT64_SIZE));
        LOGGER.debug("Length: {}", message.getLength().getValue());
    }

    private void parseBlockSize() {
        message.setBlockSize(parseIntField(DataFormatConstants.UINT32_SIZE));
        LOGGER.debug("BlockSize: {}", message.getBlockSize().getValue());
    }

    @Override
    protected void parseRequestExtendedWithPathSpecificContents() {
        parseHashAlgorithms();
        parseStartOffset();
        parseLength();
        parseBlockSize();
    }
}
