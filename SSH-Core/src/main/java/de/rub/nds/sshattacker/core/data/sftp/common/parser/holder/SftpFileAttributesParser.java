/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.common.parser.holder;

import de.rub.nds.sshattacker.core.constants.SftpFileAttributeFlag;
import de.rub.nds.sshattacker.core.data.sftp.common.message.holder.SftpFileAttributes;
import de.rub.nds.sshattacker.core.protocol.common.Parser;
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
        int flags = parseIntField();
        attributes.setFlags(flags);
        LOGGER.debug("Flags: {}", flags);
    }

    private void parseSize() {
        long size = parseLongField();
        attributes.setSize(size);
        LOGGER.debug("Size: {}", size);
    }

    private void parseUIdGId() {
        int uId = parseIntField();
        attributes.setUserId(uId);
        LOGGER.debug("UId: {}", uId);
        int gId = parseIntField();
        attributes.setGroupId(gId);
        LOGGER.debug("GId: {}", gId);
    }

    private void parsePermissions() {
        int permissions = parseIntField();
        attributes.setPermissions(permissions);
        LOGGER.debug("Permissions: {}", permissions);
    }

    private void parseAcModTime() {
        int aTime = parseIntField();
        attributes.setAccessTime(aTime);
        LOGGER.debug("ATime: {}", aTime);
        int mTime = parseIntField();
        attributes.setModifyTime(mTime);
        LOGGER.debug("MTime: {}", mTime);
    }

    private void parseExtendedAttributes() {
        int extendedCount = parseIntField();
        attributes.setExtendedCount(extendedCount);
        LOGGER.debug("ExtendedCount: {}", extendedCount);

        for (int extendedAttrIndex = 0, extendedAttrStartPointer = getPointer();
                extendedAttrIndex < extendedCount;
                extendedAttrIndex++, extendedAttrStartPointer = getPointer()) {

            SftpFileExtendedAttributeParser extendedAttrParser =
                    new SftpFileExtendedAttributeParser(getArray(), extendedAttrStartPointer);

            attributes.addExtendedAttribute(extendedAttrParser.parse(), true);
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
