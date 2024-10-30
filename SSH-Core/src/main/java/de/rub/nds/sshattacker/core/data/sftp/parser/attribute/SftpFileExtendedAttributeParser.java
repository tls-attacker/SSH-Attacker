/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.parser.attribute;

import static de.rub.nds.modifiablevariable.util.StringUtil.backslashEscapeString;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.sshattacker.core.constants.BinaryPacketConstants;
import de.rub.nds.sshattacker.core.constants.DataFormatConstants;
import de.rub.nds.sshattacker.core.data.sftp.message.attribute.SftpFileExtendedAttribute;
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
        attribute.setTypeLength(parseIntField(DataFormatConstants.STRING_SIZE_LENGTH));
        LOGGER.debug("Type length: {}", attribute.getTypeLength().getValue());
        attribute.setType(
                parseByteString(attribute.getTypeLength().getValue(), StandardCharsets.US_ASCII));
        LOGGER.debug("Type: {}", () -> backslashEscapeString(attribute.getType().getValue()));
    }

    private void parseData() {
        attribute.setDataLength(parseIntField(BinaryPacketConstants.LENGTH_FIELD_LENGTH));
        LOGGER.debug("Data length: {}", attribute.getDataLength().getValue());
        attribute.setData(parseByteArrayField(attribute.getDataLength().getValue()));
        LOGGER.debug(
                "Data: {}",
                () -> ArrayConverter.bytesToRawHexString(attribute.getData().getValue()));
    }

    @Override
    public final SftpFileExtendedAttribute parse() {
        parseType();
        parseData();
        return attribute;
    }
}
