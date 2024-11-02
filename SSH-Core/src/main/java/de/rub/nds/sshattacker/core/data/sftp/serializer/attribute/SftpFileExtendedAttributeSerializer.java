/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.serializer.attribute;

import static de.rub.nds.modifiablevariable.util.StringUtil.backslashEscapeString;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.sshattacker.core.constants.DataFormatConstants;
import de.rub.nds.sshattacker.core.data.sftp.message.attribute.SftpFileExtendedAttribute;
import de.rub.nds.sshattacker.core.protocol.common.Serializer;
import java.nio.charset.StandardCharsets;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class SftpFileExtendedAttributeSerializer extends Serializer<SftpFileExtendedAttribute> {

    private static final Logger LOGGER = LogManager.getLogger();

    private final SftpFileExtendedAttribute attribute;

    public SftpFileExtendedAttributeSerializer(SftpFileExtendedAttribute attribute) {
        super();
        this.attribute = attribute;
    }

    private void serializeType() {
        Integer typeLength = attribute.getTypeLength().getValue();
        LOGGER.debug("Type length: {}", typeLength);
        appendInt(typeLength, DataFormatConstants.STRING_SIZE_LENGTH);
        String type = attribute.getType().getValue();
        LOGGER.debug("Type: {}", () -> backslashEscapeString(type));
        appendString(type, StandardCharsets.US_ASCII);
    }

    private void serializeData() {
        Integer dataLength = attribute.getDataLength().getValue();
        LOGGER.debug("Data length: {}", dataLength);
        appendInt(dataLength, DataFormatConstants.STRING_SIZE_LENGTH);
        byte[] data = attribute.getData().getValue();
        LOGGER.debug("Data: {}", () -> ArrayConverter.bytesToRawHexString(data));
        appendBytes(data);
    }

    @Override
    protected final void serializeBytes() {
        serializeType();
        serializeData();
    }
}
