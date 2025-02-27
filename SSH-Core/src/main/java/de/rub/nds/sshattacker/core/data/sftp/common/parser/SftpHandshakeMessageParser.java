/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.common.parser;

import de.rub.nds.sshattacker.core.constants.SftpExtension;
import de.rub.nds.sshattacker.core.data.sftp.SftpMessageParser;
import de.rub.nds.sshattacker.core.data.sftp.common.message.SftpHandshakeMessage;
import de.rub.nds.sshattacker.core.data.sftp.common.message.extension.*;
import de.rub.nds.sshattacker.core.data.sftp.common.parser.extension.*;
import java.nio.charset.StandardCharsets;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public abstract class SftpHandshakeMessageParser<T extends SftpHandshakeMessage<T>>
        extends SftpMessageParser<T> {

    private static final Logger LOGGER = LogManager.getLogger();

    protected SftpHandshakeMessageParser(byte[] array) {
        super(array);
    }

    protected SftpHandshakeMessageParser(byte[] array, int startPosition) {
        super(array, startPosition);
    }

    private void parseVersion() {
        int version = parseIntField();
        message.setVersion(version);
        LOGGER.debug("Version: {}", version);
    }

    private void parseExtensions() {
        int extensionStartPointer;
        int extensionIndex = 0;
        while (getBytesLeft() > 0) {
            extensionStartPointer = getPointer();
            // Parse extension name to determine the parser to use
            int extensionNameLength = parseIntField();
            SftpExtension extension =
                    SftpExtension.fromName(
                            parseByteString(extensionNameLength, StandardCharsets.US_ASCII));
            SftpAbstractExtensionParser<?> extensionParser =
                    switch (extension) {
                        case VENDOR_ID ->
                                new SftpExtensionVendorIdParser(getArray(), extensionStartPointer);
                        case CHECK_FILE ->
                                new SftpExtensionWithVersionParser<>(
                                        SftpExtensionCheckFile::new,
                                        getArray(),
                                        extensionStartPointer);
                        case SPACE_AVAILABLE ->
                                new SftpExtensionWithVersionParser<>(
                                        SftpExtensionSpaceAvailable::new,
                                        getArray(),
                                        extensionStartPointer);
                        case HOME_DIRECTORY ->
                                new SftpExtensionWithVersionParser<>(
                                        SftpExtensionHomeDirectory::new,
                                        getArray(),
                                        extensionStartPointer);
                        case COPY_FILE ->
                                new SftpExtensionWithVersionParser<>(
                                        SftpExtensionCopyFile::new,
                                        getArray(),
                                        extensionStartPointer);
                        case COPY_DATA ->
                                new SftpExtensionWithVersionParser<>(
                                        SftpExtensionCopyData::new,
                                        getArray(),
                                        extensionStartPointer);
                        case GET_TEMP_FOLDER ->
                                new SftpExtensionWithVersionParser<>(
                                        SftpExtensionGetTempFolder::new,
                                        getArray(),
                                        extensionStartPointer);
                        case MAKE_TEMP_FOLDER ->
                                new SftpExtensionWithVersionParser<>(
                                        SftpExtensionMakeTempFolder::new,
                                        getArray(),
                                        extensionStartPointer);
                        // SFTP v4
                        case TEXT_SEEK ->
                                new SftpExtensionWithVersionParser<>(
                                        SftpExtensionTextSeek::new,
                                        getArray(),
                                        extensionStartPointer);
                        case NEWLINE ->
                                new SftpExtensionNewlineParser(getArray(), extensionStartPointer);
                        // Vendor extensions
                        case POSIX_RENAME_OPENSSH_COM ->
                                new SftpExtensionWithVersionParser<>(
                                        SftpExtensionPosixRename::new,
                                        getArray(),
                                        extensionStartPointer);
                        case STAT_VFS_OPENSSH_COM ->
                                new SftpExtensionWithVersionParser<>(
                                        SftpExtensionStatVfs::new,
                                        getArray(),
                                        extensionStartPointer);
                        case F_STAT_VFS_OPENSSH_COM ->
                                new SftpExtensionWithVersionParser<>(
                                        SftpExtensionFileStatVfs::new,
                                        getArray(),
                                        extensionStartPointer);
                        case HARDLINK_OPENSSH_COM ->
                                new SftpExtensionWithVersionParser<>(
                                        SftpExtensionHardlink::new,
                                        getArray(),
                                        extensionStartPointer);
                        case F_SYNC_OPENSSH_COM ->
                                new SftpExtensionWithVersionParser<>(
                                        SftpExtensionFileSync::new,
                                        getArray(),
                                        extensionStartPointer);
                        case L_SET_STAT ->
                                new SftpExtensionWithVersionParser<>(
                                        SftpExtensionLinkSetStat::new,
                                        getArray(),
                                        extensionStartPointer);
                        case LIMITS ->
                                new SftpExtensionWithVersionParser<>(
                                        SftpExtensionLimits::new,
                                        getArray(),
                                        extensionStartPointer);
                        case EXPAND_PATH ->
                                new SftpExtensionWithVersionParser<>(
                                        SftpExtensionExpandPath::new,
                                        getArray(),
                                        extensionStartPointer);
                        case USERS_GROUPS_BY_ID ->
                                new SftpExtensionWithVersionParser<>(
                                        SftpExtensionUsersGroupsById::new,
                                        getArray(),
                                        extensionStartPointer);
                        default -> {
                            LOGGER.debug(
                                    "Extension [{}] (index {}) is unknown or not implemented, parsing as UnknownExtension",
                                    extension,
                                    extensionIndex);
                            yield new SftpExtensionUnknownParser(getArray(), extensionStartPointer);
                        }
                    };
            message.addExtension(extensionParser.parse());
            setPointer(extensionParser.getPointer());
            extensionIndex++;
        }
    }

    @Override
    protected void parseMessageSpecificContents() {
        parseVersion();
        parseExtensions();
    }
}
