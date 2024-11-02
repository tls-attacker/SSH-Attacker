/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.serializer.extended_response;

import static de.rub.nds.modifiablevariable.util.StringUtil.backslashEscapeString;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.sshattacker.core.constants.DataFormatConstants;
import de.rub.nds.sshattacker.core.data.sftp.message.extended_response.SftpResponseCheckFileMessage;
import de.rub.nds.sshattacker.core.data.sftp.serializer.response.SftpResponseMessageSerializer;
import java.nio.charset.StandardCharsets;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class SftpResponseCheckFileMessageSerializer
        extends SftpResponseMessageSerializer<SftpResponseCheckFileMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public SftpResponseCheckFileMessageSerializer(SftpResponseCheckFileMessage message) {
        super(message);
    }

    private void serializeUsedHashAlgorithm() {
        LOGGER.debug(
                "UsedHashAlgorithm length: {}", message.getUsedHashAlgorithmLength().getValue());
        appendInt(
                message.getUsedHashAlgorithmLength().getValue(),
                DataFormatConstants.STRING_SIZE_LENGTH);
        LOGGER.debug(
                "UsedHashAlgorithm: {}",
                () -> backslashEscapeString(message.getUsedHashAlgorithm().getValue()));
        appendString(message.getUsedHashAlgorithm().getValue(), StandardCharsets.US_ASCII);
    }

    private void serializeHash() {
        LOGGER.debug(
                "Hash: {}", () -> ArrayConverter.bytesToRawHexString(message.getHash().getValue()));
        appendBytes(message.getHash().getValue());
    }

    @Override
    protected void serializeResponseSpecificContents() {
        serializeUsedHashAlgorithm();
        serializeHash();
    }
}
