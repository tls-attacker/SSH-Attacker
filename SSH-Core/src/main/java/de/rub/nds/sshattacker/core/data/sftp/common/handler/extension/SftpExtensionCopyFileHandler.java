/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.common.handler.extension;

import de.rub.nds.sshattacker.core.constants.SftpExtension;
import de.rub.nds.sshattacker.core.data.sftp.common.message.extension.SftpExtensionCopyFile;
import de.rub.nds.sshattacker.core.data.sftp.common.parser.extension.SftpExtensionWithVersionParser;
import de.rub.nds.sshattacker.core.data.sftp.common.preperator.extension.SftpExtensionWithVersionPreparator;
import de.rub.nds.sshattacker.core.data.sftp.common.serializer.extension.SftpExtensionWithVersionSerializer;
import de.rub.nds.sshattacker.core.state.SshContext;

public class SftpExtensionCopyFileHandler
        extends SftpAbstractExtensionHandler<SftpExtensionCopyFile> {

    @Override
    public void adjustContext(SshContext context, SftpExtensionCopyFile object) {}

    @Override
    public SftpExtensionWithVersionParser<SftpExtensionCopyFile> getParser(
            byte[] array, SshContext context) {
        return new SftpExtensionWithVersionParser<>(SftpExtensionCopyFile::new, array);
    }

    @Override
    public SftpExtensionWithVersionParser<SftpExtensionCopyFile> getParser(
            byte[] array, int startPosition, SshContext context) {
        return new SftpExtensionWithVersionParser<>(
                SftpExtensionCopyFile::new, array, startPosition);
    }

    public static final SftpExtensionWithVersionPreparator<SftpExtensionCopyFile> PREPARATOR =
            new SftpExtensionWithVersionPreparator<>(SftpExtension.COPY_FILE);

    public static final SftpExtensionWithVersionSerializer<SftpExtensionCopyFile> SERIALIZER =
            new SftpExtensionWithVersionSerializer<>();
}
