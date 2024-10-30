/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.parser.attribute;

import de.rub.nds.sshattacker.core.constants.DataFormatConstants;
import de.rub.nds.sshattacker.core.constants.SftpFileAttributeFlag;
import de.rub.nds.sshattacker.core.data.sftp.message.attribute.SftpFileAttributes;
import de.rub.nds.sshattacker.core.protocol.common.Parser;
import de.rub.nds.sshattacker.core.protocol.transport.parser.extension.*;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class SftpFileAttributesParser extends Parser<SftpFileAttributes> {

    private static final Logger LOGGER = LogManager.getLogger();

    private final SftpFileAttributes attributes = new SftpFileAttributes();

    public SftpFileAttributesParser(byte[] array) {
        super(array);
    }

    public SftpFileAttributesParser(byte[] array, int startPosition) {
        super(array, startPosition);
    }

    private void parseFlags() {
        attributes.setFlags(parseIntField(DataFormatConstants.UINT32_SIZE));
        LOGGER.debug("Flags: {}", attributes.getFlags().getValue());
    }

    private void parseSize() {
        attributes.setSize(parseLongField(DataFormatConstants.UINT64_SIZE));
        LOGGER.debug("Size: {}", attributes.getSize().getValue());
    }

    private void parseUIdGId() {
        attributes.setUId(parseIntField(DataFormatConstants.UINT32_SIZE));
        LOGGER.debug("UId: {}", attributes.getUId().getValue());
        attributes.setGId(parseIntField(DataFormatConstants.UINT32_SIZE));
        LOGGER.debug("GId: {}", attributes.getGId().getValue());
    }

    private void parsePermissions() {
        attributes.setPermissions(parseIntField(DataFormatConstants.UINT32_SIZE));
        LOGGER.debug("Permissions: {}", attributes.getPermissions().getValue());
    }

    private void parseAcModTime() {
        attributes.setATime(parseIntField(DataFormatConstants.UINT32_SIZE));
        LOGGER.debug("ATime: {}", attributes.getATime().getValue());
        attributes.setMTime(parseIntField(DataFormatConstants.UINT32_SIZE));
        LOGGER.debug("MTime: {}", attributes.getMTime().getValue());
    }

    private void parseExtendedAttributes() {
        attributes.setExtendedCount(parseIntField(DataFormatConstants.UINT32_SIZE));
        LOGGER.debug("ExtendedCount: {}", attributes.getExtendedCount().getValue());

        for (int extendedAttrIndex = 0, extendedAttrStartPointer = getPointer();
                extendedAttrIndex < attributes.getExtendedCount().getValue();
                extendedAttrIndex++, extendedAttrStartPointer = getPointer()) {

            SftpFileExtendedAttributeParser extendedAttrParser =
                    new SftpFileExtendedAttributeParser(getArray(), extendedAttrStartPointer);

            attributes.addExtendedAttribute(extendedAttrParser.parse());
            setPointer(extendedAttrParser.getPointer());
        }
    }

    @Override
    public final SftpFileAttributes parse() {
        parseFlags();
        int flags = attributes.getFlags().getValue();
        if (isFlagSet(flags, SftpFileAttributeFlag.SSH_FILEXFER_ATTR_SIZE)) {
            parseSize();
        }
        if (isFlagSet(flags, SftpFileAttributeFlag.SSH_FILEXFER_ATTR_UIDGID)) {
            parseUIdGId();
        }
        if (isFlagSet(flags, SftpFileAttributeFlag.SSH_FILEXFER_ATTR_PERMISSIONS)) {
            parsePermissions();
        }
        if (isFlagSet(flags, SftpFileAttributeFlag.SSH_FILEXFER_ATTR_ACMODTIME)) {
            parseAcModTime();
        }
        if (isFlagSet(flags, SftpFileAttributeFlag.SSH_FILEXFER_ATTR_EXTENDED)) {
            parseExtendedAttributes();
        }
        return attributes;
    }

    private static boolean isFlagSet(int attributes, SftpFileAttributeFlag attribute) {
        return (attributes & attribute.getValue()) != 0;
    }
}
