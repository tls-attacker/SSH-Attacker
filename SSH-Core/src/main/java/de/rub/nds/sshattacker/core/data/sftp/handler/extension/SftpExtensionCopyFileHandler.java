/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.handler.extension;

import de.rub.nds.sshattacker.core.constants.SftpExtension;
import de.rub.nds.sshattacker.core.data.sftp.message.extension.SftpExtensionCopyFile;
import de.rub.nds.sshattacker.core.data.sftp.parser.extension.SftpExtensionWithVersionParser;
import de.rub.nds.sshattacker.core.data.sftp.preperator.extension.SftpExtensionWithVersionPreparator;
import de.rub.nds.sshattacker.core.data.sftp.serializer.extension.SftpExtensionWithVersionSerializer;
import de.rub.nds.sshattacker.core.state.SshContext;

public class SftpExtensionCopyFileHandler
        extends SftpAbstractExtensionHandler<SftpExtensionCopyFile> {

    public SftpExtensionCopyFileHandler(SshContext context) {
        super(context);
    }

    public SftpExtensionCopyFileHandler(SshContext context, SftpExtensionCopyFile extension) {
        super(context, extension);
    }

    @Override
    public void adjustContext() {
        // TODO: Handle SftpUnknownExtension
    }

    @Override
    public SftpExtensionWithVersionParser<SftpExtensionCopyFile> getParser(byte[] array) {
        return new SftpExtensionWithVersionParser<>(SftpExtensionCopyFile::new, array);
    }

    @Override
    public SftpExtensionWithVersionParser<SftpExtensionCopyFile> getParser(
            byte[] array, int startPosition) {
        return new SftpExtensionWithVersionParser<>(
                SftpExtensionCopyFile::new, array, startPosition);
    }

    public static final SftpExtensionWithVersionPreparator<SftpExtensionCopyFile> PREPARATOR =
            new SftpExtensionWithVersionPreparator<>(SftpExtension.COPY_FILE);

    @Override
    public SftpExtensionWithVersionSerializer<SftpExtensionCopyFile> getSerializer() {
        return new SftpExtensionWithVersionSerializer<>(extension);
    }
}
