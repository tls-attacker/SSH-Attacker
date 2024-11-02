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
        Integer usedHashAlgorithmLength = message.getUsedHashAlgorithmLength().getValue();
        LOGGER.debug("UsedHashAlgorithm length: {}", usedHashAlgorithmLength);
        appendInt(usedHashAlgorithmLength, DataFormatConstants.STRING_SIZE_LENGTH);
        String usedHashAlgorithm = message.getUsedHashAlgorithm().getValue();
        LOGGER.debug("UsedHashAlgorithm: {}", () -> backslashEscapeString(usedHashAlgorithm));
        appendString(usedHashAlgorithm, StandardCharsets.US_ASCII);
    }

    private void serializeHash() {
        byte[] hash = message.getHash().getValue();
        LOGGER.debug("Hash: {}", () -> ArrayConverter.bytesToRawHexString(hash));
        appendBytes(hash);
    }

    @Override
    protected void serializeResponseSpecificContents() {
        serializeUsedHashAlgorithm();
        serializeHash();
    }
}
