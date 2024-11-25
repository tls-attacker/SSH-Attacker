/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.parser.holder;

import static de.rub.nds.modifiablevariable.util.StringUtil.backslashEscapeString;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.sshattacker.core.constants.DataFormatConstants;
import de.rub.nds.sshattacker.core.data.sftp.message.holder.SftpFileExtendedAttribute;
import de.rub.nds.sshattacker.core.protocol.common.Parser;
import java.nio.charset.StandardCharsets;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class SftpFileExtendedAttributeParser extends Parser<SftpFileExtendedAttribute> {

    private static final Logger LOGGER = LogManager.getLogger();

    private final SftpFileExtendedAttribute attribute = new SftpFileExtendedAttribute();

    public SftpFileExtendedAttributeParser(byte[] array) {
        super(array);
    }

    public SftpFileExtendedAttributeParser(byte[] array, int startPosition) {
        super(array, startPosition);
    }

    private void parseType() {
        int typeLength = parseIntField(DataFormatConstants.STRING_SIZE_LENGTH);
        attribute.setTypeLength(typeLength);
        LOGGER.debug("Type length: {}", typeLength);
        String type = parseByteString(typeLength, StandardCharsets.US_ASCII);
        attribute.setType(type);
        LOGGER.debug("Type: {}", () -> backslashEscapeString(type));
    }

    private void parseData() {
        int dataLength = parseIntField(DataFormatConstants.STRING_SIZE_LENGTH);
        attribute.setDataLength(dataLength);
        LOGGER.debug("Data length: {}", dataLength);
        byte[] data = parseByteArrayField(dataLength);
        attribute.setData(data);
        LOGGER.debug("Data: {}", () -> ArrayConverter.bytesToRawHexString(data));
    }

    @Override
    public final SftpFileExtendedAttribute parse() {
        parseType();
        parseData();
        return attribute;
    }
}
