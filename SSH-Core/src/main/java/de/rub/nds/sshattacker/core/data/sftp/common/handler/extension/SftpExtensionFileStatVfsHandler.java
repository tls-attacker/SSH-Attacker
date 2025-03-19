/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.common.handler.extension;

import de.rub.nds.sshattacker.core.data.sftp.common.message.extension.SftpExtensionFileStatVfs;
import de.rub.nds.sshattacker.core.data.sftp.common.parser.extension.SftpExtensionWithVersionParser;
import de.rub.nds.sshattacker.core.data.sftp.common.preparator.extension.SftpExtensionFileStatVfsPreparator;
import de.rub.nds.sshattacker.core.data.sftp.common.serializer.extension.SftpExtensionWithVersionSerializer;
import de.rub.nds.sshattacker.core.state.SshContext;

public class SftpExtensionFileStatVfsHandler
        extends SftpAbstractExtensionHandler<SftpExtensionFileStatVfs> {

    @Override
    public void adjustContext(SshContext context, SftpExtensionFileStatVfs object) {}

    @Override
    public SftpExtensionWithVersionParser<SftpExtensionFileStatVfs> getParser(
            byte[] array, SshContext context) {
        return new SftpExtensionWithVersionParser<>(SftpExtensionFileStatVfs::new, array);
    }

    @Override
    public SftpExtensionWithVersionParser<SftpExtensionFileStatVfs> getParser(
            byte[] array, int startPosition, SshContext context) {
        return new SftpExtensionWithVersionParser<>(
                SftpExtensionFileStatVfs::new, array, startPosition);
    }

    public static final SftpExtensionFileStatVfsPreparator PREPARATOR =
            new SftpExtensionFileStatVfsPreparator();

    public static final SftpExtensionWithVersionSerializer<SftpExtensionFileStatVfs> SERIALIZER =
            new SftpExtensionWithVersionSerializer<>();
}
