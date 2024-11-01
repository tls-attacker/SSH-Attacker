/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.handler.extension;

import de.rub.nds.sshattacker.core.constants.SftpExtension;
import de.rub.nds.sshattacker.core.data.sftp.message.extension.SftpExtensionFileStatVfs;
import de.rub.nds.sshattacker.core.data.sftp.parser.extension.SftpExtensionWithVersionParser;
import de.rub.nds.sshattacker.core.data.sftp.preperator.extension.SftpExtensionWithVersionPreparator;
import de.rub.nds.sshattacker.core.data.sftp.serializer.extension.SftpExtensionWithVersionSerializer;
import de.rub.nds.sshattacker.core.state.SshContext;

public class SftpExtensionFileStatVfsHandler
        extends SftpAbstractExtensionHandler<SftpExtensionFileStatVfs> {

    public SftpExtensionFileStatVfsHandler(SshContext context) {
        super(context);
    }

    public SftpExtensionFileStatVfsHandler(SshContext context, SftpExtensionFileStatVfs extension) {
        super(context, extension);
    }

    @Override
    public void adjustContext() {
        // TODO: Handle SftpUnknownExtension
    }

    @Override
    public SftpExtensionWithVersionParser<SftpExtensionFileStatVfs> getParser(byte[] array) {
        return new SftpExtensionWithVersionParser<>(SftpExtensionFileStatVfs::new, array);
    }

    @Override
    public SftpExtensionWithVersionParser<SftpExtensionFileStatVfs> getParser(
            byte[] array, int startPosition) {
        return new SftpExtensionWithVersionParser<>(
                SftpExtensionFileStatVfs::new, array, startPosition);
    }

    @Override
    public SftpExtensionWithVersionPreparator<SftpExtensionFileStatVfs> getPreparator() {
        return new SftpExtensionWithVersionPreparator<>(
                context.getChooser(), extension, SftpExtension.F_STAT_VFS_OPENSSH_COM);
    }

    @Override
    public SftpExtensionWithVersionSerializer<SftpExtensionFileStatVfs> getSerializer() {
        return new SftpExtensionWithVersionSerializer<>(extension);
    }
}
