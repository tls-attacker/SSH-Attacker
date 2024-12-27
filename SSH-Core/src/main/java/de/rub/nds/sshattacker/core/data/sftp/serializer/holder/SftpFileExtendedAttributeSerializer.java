/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.serializer.holder;

import static de.rub.nds.modifiablevariable.util.StringUtil.backslashEscapeString;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.sshattacker.core.constants.DataFormatConstants;
import de.rub.nds.sshattacker.core.data.sftp.message.holder.SftpFileExtendedAttribute;
import de.rub.nds.sshattacker.core.protocol.common.Serializer;
import de.rub.nds.sshattacker.core.protocol.common.SerializerStream;
import java.nio.charset.StandardCharsets;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class SftpFileExtendedAttributeSerializer extends Serializer<SftpFileExtendedAttribute> {

    private static final Logger LOGGER = LogManager.getLogger();

    private static void serializeType(SftpFileExtendedAttribute object, SerializerStream output) {
        Integer typeLength = object.getTypeLength().getValue();
        LOGGER.debug("Type length: {}", typeLength);
        output.appendInt(typeLength, DataFormatConstants.STRING_SIZE_LENGTH);
        String type = object.getType().getValue();
        LOGGER.debug("Type: {}", () -> backslashEscapeString(type));
        output.appendString(type, StandardCharsets.US_ASCII);
    }

    private static void serializeData(SftpFileExtendedAttribute object, SerializerStream output) {
        Integer dataLength = object.getDataLength().getValue();
        LOGGER.debug("Data length: {}", dataLength);
        output.appendInt(dataLength, DataFormatConstants.STRING_SIZE_LENGTH);
        byte[] data = object.getData().getValue();
        LOGGER.debug("Data: {}", () -> ArrayConverter.bytesToRawHexString(data));
        output.appendBytes(data);
    }

    @Override
    protected final void serializeBytes(SftpFileExtendedAttribute object, SerializerStream output) {
        serializeType(object, output);
        serializeData(object, output);
    }
}
