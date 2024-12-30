/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.serializer.extended_request;

import static de.rub.nds.modifiablevariable.util.StringUtil.backslashEscapeString;

import de.rub.nds.sshattacker.core.data.sftp.message.extended_request.SftpRequestCheckFileNameMessage;
import de.rub.nds.sshattacker.core.protocol.common.SerializerStream;
import java.nio.charset.StandardCharsets;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class SftpRequestCheckFileNameMessageSerializer
        extends SftpRequestExtendedWithPathMessageSerializer<SftpRequestCheckFileNameMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    private static void serializeHashAlgorithms(
            SftpRequestCheckFileNameMessage object, SerializerStream output) {
        Integer hashAlgorithmsLength = object.getHashAlgorithmsLength().getValue();
        LOGGER.debug("HashAlgorithms length: {}", hashAlgorithmsLength);
        output.appendInt(hashAlgorithmsLength);
        String hashAlgorithms = object.getHashAlgorithms().getValue();
        LOGGER.debug("HashAlgorithms: {}", () -> backslashEscapeString(hashAlgorithms));
        output.appendString(hashAlgorithms, StandardCharsets.US_ASCII);
    }

    private static void serializeStartOffset(
            SftpRequestCheckFileNameMessage object, SerializerStream output) {
        Long startOffset = object.getStartOffset().getValue();
        LOGGER.debug("StartOffset: {}", startOffset);
        output.appendLong(startOffset);
    }

    private static void serializeLength(
            SftpRequestCheckFileNameMessage object, SerializerStream output) {
        Long length = object.getLength().getValue();
        LOGGER.debug("Length: {}", length);
        output.appendLong(length);
    }

    private static void serializeBlockSize(
            SftpRequestCheckFileNameMessage object, SerializerStream output) {
        Integer blockSize = object.getBlockSize().getValue();
        LOGGER.debug("BlockSize: {}", blockSize);
        output.appendInt(blockSize);
    }

    @Override
    protected void serializeRequestExtendedWithPathSpecificContents(
            SftpRequestCheckFileNameMessage object, SerializerStream output) {
        serializeHashAlgorithms(object, output);
        serializeStartOffset(object, output);
        serializeLength(object, output);
        serializeBlockSize(object, output);
    }
}
