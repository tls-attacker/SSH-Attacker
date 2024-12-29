/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.parser;

import de.rub.nds.sshattacker.core.constants.DataFormatConstants;
import de.rub.nds.sshattacker.core.constants.SftpExtension;
import de.rub.nds.sshattacker.core.data.sftp.SftpMessageParser;
import de.rub.nds.sshattacker.core.data.sftp.message.SftpHandshakeMessage;
import de.rub.nds.sshattacker.core.data.sftp.message.extension.*;
import de.rub.nds.sshattacker.core.data.sftp.parser.extension.*;
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
        int version = parseIntField(DataFormatConstants.UINT32_SIZE);
        message.setVersion(version);
        LOGGER.debug("Version: {}", version);
    }

    private void parseExtensions() {
        int extensionStartPointer;
        int extensionIndex = 0;
        while (getBytesLeft() > 0) {
            extensionStartPointer = getPointer();
            // Parse extension name to determine the parser to use
            int extensionNameLength = parseIntField(DataFormatConstants.UINT32_SIZE);
            SftpExtension extension =
                    SftpExtension.fromName(
                            parseByteString(extensionNameLength, StandardCharsets.US_ASCII));
            SftpAbstractExtensionParser<?> extensionParser;
            switch (extension) {
                case VENDOR_ID:
                    extensionParser =
                            new SftpExtensionVendorIdParser(getArray(), extensionStartPointer);
                    break;
                case CHECK_FILE:
                    extensionParser =
                            new SftpExtensionWithVersionParser<>(
                                    SftpExtensionCheckFile::new, getArray(), extensionStartPointer);
                    break;
                case SPACE_AVAILABLE:
                    extensionParser =
                            new SftpExtensionWithVersionParser<>(
                                    SftpExtensionSpaceAvailable::new,
                                    getArray(),
                                    extensionStartPointer);
                    break;
                case HOME_DIRECTORY:
                    extensionParser =
                            new SftpExtensionWithVersionParser<>(
                                    SftpExtensionHomeDirectory::new,
                                    getArray(),
                                    extensionStartPointer);
                    break;
                case COPY_FILE:
                    extensionParser =
                            new SftpExtensionWithVersionParser<>(
                                    SftpExtensionCopyFile::new, getArray(), extensionStartPointer);
                    break;
                case COPY_DATA:
                    extensionParser =
                            new SftpExtensionWithVersionParser<>(
                                    SftpExtensionCopyData::new, getArray(), extensionStartPointer);
                    break;
                case GET_TEMP_FOLDER:
                    extensionParser =
                            new SftpExtensionWithVersionParser<>(
                                    SftpExtensionGetTempFolder::new,
                                    getArray(),
                                    extensionStartPointer);
                    break;
                case MAKE_TEMP_FOLDER:
                    extensionParser =
                            new SftpExtensionWithVersionParser<>(
                                    SftpExtensionMakeTempFolder::new,
                                    getArray(),
                                    extensionStartPointer);
                    break;
                    // SFTP v4
                case TEXT_SEEK:
                    extensionParser =
                            new SftpExtensionWithVersionParser<>(
                                    SftpExtensionTextSeek::new, getArray(), extensionStartPointer);
                    break;
                case NEWLINE:
                    extensionParser =
                            new SftpExtensionNewlineParser(getArray(), extensionStartPointer);
                    break;
                    // Vendor extensions
                case POSIX_RENAME_OPENSSH_COM:
                    extensionParser =
                            new SftpExtensionWithVersionParser<>(
                                    SftpExtensionPosixRename::new,
                                    getArray(),
                                    extensionStartPointer);
                    break;
                case STAT_VFS_OPENSSH_COM:
                    extensionParser =
                            new SftpExtensionWithVersionParser<>(
                                    SftpExtensionStatVfs::new, getArray(), extensionStartPointer);
                    break;
                case F_STAT_VFS_OPENSSH_COM:
                    extensionParser =
                            new SftpExtensionWithVersionParser<>(
                                    SftpExtensionFileStatVfs::new,
                                    getArray(),
                                    extensionStartPointer);
                    break;
                case HARDLINK_OPENSSH_COM:
                    extensionParser =
                            new SftpExtensionWithVersionParser<>(
                                    SftpExtensionHardlink::new, getArray(), extensionStartPointer);
                    break;
                case F_SYNC_OPENSSH_COM:
                    extensionParser =
                            new SftpExtensionWithVersionParser<>(
                                    SftpExtensionFileSync::new, getArray(), extensionStartPointer);
                    break;
                case L_SET_STAT:
                    extensionParser =
                            new SftpExtensionWithVersionParser<>(
                                    SftpExtensionLinkSetStat::new,
                                    getArray(),
                                    extensionStartPointer);
                    break;
                case LIMITS:
                    extensionParser =
                            new SftpExtensionWithVersionParser<>(
                                    SftpExtensionLimits::new, getArray(), extensionStartPointer);
                    break;
                case EXPAND_PATH:
                    extensionParser =
                            new SftpExtensionWithVersionParser<>(
                                    SftpExtensionExpandPath::new,
                                    getArray(),
                                    extensionStartPointer);
                    break;
                case USERS_GROUPS_BY_ID:
                    extensionParser =
                            new SftpExtensionWithVersionParser<>(
                                    SftpExtensionUsersGroupsById::new,
                                    getArray(),
                                    extensionStartPointer);
                    break;

                default:
                    LOGGER.debug(
                            "Extension [{}] (index {}) is unknown or not implemented, parsing as UnknownExtension",
                            extension,
                            extensionIndex);
                    extensionParser =
                            new SftpExtensionUnknownParser(getArray(), extensionStartPointer);
                    break;
            }
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
