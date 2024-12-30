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
import de.rub.nds.sshattacker.core.data.sftp.message.extended_response.SftpResponseCheckFileMessage;
import de.rub.nds.sshattacker.core.data.sftp.serializer.response.SftpResponseMessageSerializer;
import de.rub.nds.sshattacker.core.protocol.common.SerializerStream;
import java.nio.charset.StandardCharsets;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class SftpResponseCheckFileMessageSerializer
        extends SftpResponseMessageSerializer<SftpResponseCheckFileMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    private static void serializeUsedHashAlgorithm(
            SftpResponseCheckFileMessage object, SerializerStream output) {
        Integer usedHashAlgorithmLength = object.getUsedHashAlgorithmLength().getValue();
        LOGGER.debug("UsedHashAlgorithm length: {}", usedHashAlgorithmLength);
        output.appendInt(usedHashAlgorithmLength);
        String usedHashAlgorithm = object.getUsedHashAlgorithm().getValue();
        LOGGER.debug("UsedHashAlgorithm: {}", () -> backslashEscapeString(usedHashAlgorithm));
        output.appendString(usedHashAlgorithm, StandardCharsets.US_ASCII);
    }

    private static void serializeHash(
            SftpResponseCheckFileMessage object, SerializerStream output) {
        byte[] hash = object.getHash().getValue();
        LOGGER.debug("Hash: {}", () -> ArrayConverter.bytesToRawHexString(hash));
        output.appendBytes(hash);
    }

    @Override
    protected void serializeResponseSpecificContents(
            SftpResponseCheckFileMessage object, SerializerStream output) {
        serializeUsedHashAlgorithm(object, output);
        serializeHash(object, output);
    }
}
