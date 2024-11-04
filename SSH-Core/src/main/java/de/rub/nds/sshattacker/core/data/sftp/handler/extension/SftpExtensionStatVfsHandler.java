/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.handler.extension;

import de.rub.nds.sshattacker.core.constants.SftpExtension;
import de.rub.nds.sshattacker.core.data.sftp.message.extension.SftpExtensionStatVfs;
import de.rub.nds.sshattacker.core.data.sftp.parser.extension.SftpExtensionWithVersionParser;
import de.rub.nds.sshattacker.core.data.sftp.preperator.extension.SftpExtensionStatVfsPreparator;
import de.rub.nds.sshattacker.core.data.sftp.serializer.extension.SftpExtensionWithVersionSerializer;
import de.rub.nds.sshattacker.core.state.SshContext;

public class SftpExtensionStatVfsHandler
        extends SftpAbstractExtensionHandler<SftpExtensionStatVfs> {

    public SftpExtensionStatVfsHandler(SshContext context) {
        super(context);
    }

    public SftpExtensionStatVfsHandler(SshContext context, SftpExtensionStatVfs extension) {
        super(context, extension);
    }

    @Override
    public void adjustContext() {
        // TODO: Handle SftpUnknownExtension
    }

    @Override
    public SftpExtensionWithVersionParser<SftpExtensionStatVfs> getParser(byte[] array) {
        return new SftpExtensionWithVersionParser<>(SftpExtensionStatVfs::new, array);
    }

    @Override
    public SftpExtensionWithVersionParser<SftpExtensionStatVfs> getParser(
            byte[] array, int startPosition) {
        return new SftpExtensionWithVersionParser<>(
                SftpExtensionStatVfs::new, array, startPosition);
    }

    @Override
    public SftpExtensionStatVfsPreparator getPreparator() {
        return new SftpExtensionStatVfsPreparator(
                context.getChooser(), extension, SftpExtension.F_STAT_VFS_OPENSSH_COM);
    }

    @Override
    public SftpExtensionWithVersionSerializer<SftpExtensionStatVfs> getSerializer() {
        return new SftpExtensionWithVersionSerializer<>(extension);
    }
}
