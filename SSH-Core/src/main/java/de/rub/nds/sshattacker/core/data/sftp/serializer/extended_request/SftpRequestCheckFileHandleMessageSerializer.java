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
import de.rub.nds.sshattacker.core.data.sftp.message.extended_request.SftpRequestCheckFileHandleMessage;
import java.nio.charset.StandardCharsets;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class SftpRequestCheckFileHandleMessageSerializer
        extends SftpRequestExtendedWithHandleMessageSerializer<SftpRequestCheckFileHandleMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public SftpRequestCheckFileHandleMessageSerializer(SftpRequestCheckFileHandleMessage message) {
        super(message);
    }

    private void serializeHashAlgorithms() {
        LOGGER.debug("HashAlgorithms length: {}", message.getHashAlgorithmsLength().getValue());
        appendInt(
                message.getHashAlgorithmsLength().getValue(),
                DataFormatConstants.STRING_SIZE_LENGTH);
        LOGGER.debug(
                "HashAlgorithms: {}",
                () -> backslashEscapeString(message.getHashAlgorithms().getValue()));
        appendString(message.getHashAlgorithms().getValue(), StandardCharsets.US_ASCII);
    }

    private void serializeStartOffset() {
        LOGGER.debug("StartOffset: {}", message.getStartOffset().getValue());
        appendLong(message.getStartOffset().getValue(), DataFormatConstants.UINT64_SIZE);
    }

    private void serializeLength() {
        LOGGER.debug("Length: {}", message.getLength().getValue());
        appendLong(message.getLength().getValue(), DataFormatConstants.UINT64_SIZE);
    }

    private void serializeBlockSize() {
        LOGGER.debug("BlockSize: {}", message.getBlockSize().getValue());
        appendInt(message.getBlockSize().getValue(), DataFormatConstants.UINT32_SIZE);
    }

    @Override
    protected void serializeRequestExtendedWithHandleSpecificContents() {
        serializeHashAlgorithms();
        serializeStartOffset();
        serializeLength();
        serializeBlockSize();
    }
}
