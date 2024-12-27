/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.handler.extension;

import de.rub.nds.sshattacker.core.constants.SftpExtension;
import de.rub.nds.sshattacker.core.data.sftp.message.extension.SftpExtensionPosixRename;
import de.rub.nds.sshattacker.core.data.sftp.parser.extension.SftpExtensionWithVersionParser;
import de.rub.nds.sshattacker.core.data.sftp.preperator.extension.SftpExtensionWithVersionPreparator;
import de.rub.nds.sshattacker.core.data.sftp.serializer.extension.SftpExtensionWithVersionSerializer;
import de.rub.nds.sshattacker.core.state.SshContext;

public class SftpExtensionPosixRenameHandler
        extends SftpAbstractExtensionHandler<SftpExtensionPosixRename> {

    public SftpExtensionPosixRenameHandler(SshContext context) {
        super(context);
    }

    public SftpExtensionPosixRenameHandler(SshContext context, SftpExtensionPosixRename extension) {
        super(context, extension);
    }

    @Override
    public void adjustContext() {
        // TODO: Handle SftpUnknownExtension
    }

    @Override
    public SftpExtensionWithVersionParser<SftpExtensionPosixRename> getParser(byte[] array) {
        return new SftpExtensionWithVersionParser<>(SftpExtensionPosixRename::new, array);
    }

    @Override
    public SftpExtensionWithVersionParser<SftpExtensionPosixRename> getParser(
            byte[] array, int startPosition) {
        return new SftpExtensionWithVersionParser<>(
                SftpExtensionPosixRename::new, array, startPosition);
    }

    public static final SftpExtensionWithVersionPreparator<SftpExtensionPosixRename> PREPARATOR =
            new SftpExtensionWithVersionPreparator<>(SftpExtension.POSIX_RENAME_OPENSSH_COM);

    public static final SftpExtensionWithVersionSerializer<SftpExtensionPosixRename> SERIALIZER =
            new SftpExtensionWithVersionSerializer<>();
}
