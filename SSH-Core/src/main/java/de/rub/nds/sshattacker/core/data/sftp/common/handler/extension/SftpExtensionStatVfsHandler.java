/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.common.handler.extension;

import de.rub.nds.sshattacker.core.data.sftp.common.message.extension.SftpExtensionStatVfs;
import de.rub.nds.sshattacker.core.data.sftp.common.parser.extension.SftpExtensionWithVersionParser;
import de.rub.nds.sshattacker.core.data.sftp.common.preperator.extension.SftpExtensionStatVfsPreparator;
import de.rub.nds.sshattacker.core.data.sftp.common.serializer.extension.SftpExtensionWithVersionSerializer;
import de.rub.nds.sshattacker.core.state.SshContext;

public class SftpExtensionStatVfsHandler
        extends SftpAbstractExtensionHandler<SftpExtensionStatVfs> {

    @Override
    public void adjustContext(SshContext context, SftpExtensionStatVfs object) {}

    @Override
    public SftpExtensionWithVersionParser<SftpExtensionStatVfs> getParser(
            byte[] array, SshContext context) {
        return new SftpExtensionWithVersionParser<>(SftpExtensionStatVfs::new, array);
    }

    @Override
    public SftpExtensionWithVersionParser<SftpExtensionStatVfs> getParser(
            byte[] array, int startPosition, SshContext context) {
        return new SftpExtensionWithVersionParser<>(
                SftpExtensionStatVfs::new, array, startPosition);
    }

    public static final SftpExtensionStatVfsPreparator PREPARATOR =
            new SftpExtensionStatVfsPreparator();

    public static final SftpExtensionWithVersionSerializer<SftpExtensionStatVfs> SERIALIZER =
            new SftpExtensionWithVersionSerializer<>();
}
