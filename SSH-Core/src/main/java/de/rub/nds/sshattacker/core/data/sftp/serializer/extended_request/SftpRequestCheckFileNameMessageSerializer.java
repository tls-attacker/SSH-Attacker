/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.serializer.extended_request;

import static de.rub.nds.modifiablevariable.util.StringUtil.backslashEscapeString;

import de.rub.nds.sshattacker.core.constants.DataFormatConstants;
import de.rub.nds.sshattacker.core.data.sftp.message.extended_request.SftpRequestCheckFileNameMessage;
import java.nio.charset.StandardCharsets;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class SftpRequestCheckFileNameMessageSerializer
        extends SftpRequestExtendedWithPathMessageSerializer<SftpRequestCheckFileNameMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public SftpRequestCheckFileNameMessageSerializer(SftpRequestCheckFileNameMessage message) {
        super(message);
    }

    private void serializeHashAlgorithms() {
        Integer hashAlgorithmsLength = message.getHashAlgorithmsLength().getValue();
        LOGGER.debug("HashAlgorithms length: {}", hashAlgorithmsLength);
        appendInt(hashAlgorithmsLength, DataFormatConstants.STRING_SIZE_LENGTH);
        String hashAlgorithms = message.getHashAlgorithms().getValue();
        LOGGER.debug("HashAlgorithms: {}", () -> backslashEscapeString(hashAlgorithms));
        appendString(hashAlgorithms, StandardCharsets.US_ASCII);
    }

    private void serializeStartOffset() {
        Long startOffset = message.getStartOffset().getValue();
        LOGGER.debug("StartOffset: {}", startOffset);
        appendLong(startOffset, DataFormatConstants.UINT64_SIZE);
    }

    private void serializeLength() {
        Long length = message.getLength().getValue();
        LOGGER.debug("Length: {}", length);
        appendLong(length, DataFormatConstants.UINT64_SIZE);
    }

    private void serializeBlockSize() {
        Integer blockSize = message.getBlockSize().getValue();
        LOGGER.debug("BlockSize: {}", blockSize);
        appendInt(blockSize, DataFormatConstants.UINT32_SIZE);
    }

    @Override
    protected void serializeRequestExtendedWithPathSpecificContents() {
        serializeHashAlgorithms();
        serializeStartOffset();
        serializeLength();
        serializeBlockSize();
    }
}
