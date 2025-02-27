/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.common.handler.extension;

import de.rub.nds.sshattacker.core.constants.SftpExtension;
import de.rub.nds.sshattacker.core.data.sftp.common.message.extension.SftpExtensionPosixRename;
import de.rub.nds.sshattacker.core.data.sftp.common.parser.extension.SftpExtensionWithVersionParser;
import de.rub.nds.sshattacker.core.data.sftp.common.preperator.extension.SftpExtensionWithVersionPreparator;
import de.rub.nds.sshattacker.core.data.sftp.common.serializer.extension.SftpExtensionWithVersionSerializer;
import de.rub.nds.sshattacker.core.state.SshContext;

public class SftpExtensionPosixRenameHandler
        extends SftpAbstractExtensionHandler<SftpExtensionPosixRename> {

    @Override
    public void adjustContext(SshContext context, SftpExtensionPosixRename object) {}

    @Override
    public SftpExtensionWithVersionParser<SftpExtensionPosixRename> getParser(
            byte[] array, SshContext context) {
        return new SftpExtensionWithVersionParser<>(SftpExtensionPosixRename::new, array);
    }

    @Override
    public SftpExtensionWithVersionParser<SftpExtensionPosixRename> getParser(
            byte[] array, int startPosition, SshContext context) {
        return new SftpExtensionWithVersionParser<>(
                SftpExtensionPosixRename::new, array, startPosition);
    }

    public static final SftpExtensionWithVersionPreparator<SftpExtensionPosixRename> PREPARATOR =
            new SftpExtensionWithVersionPreparator<>(SftpExtension.POSIX_RENAME_OPENSSH_COM);

    public static final SftpExtensionWithVersionSerializer<SftpExtensionPosixRename> SERIALIZER =
            new SftpExtensionWithVersionSerializer<>();
}
