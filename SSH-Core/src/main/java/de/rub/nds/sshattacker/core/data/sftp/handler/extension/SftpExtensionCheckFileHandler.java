/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.handler.extension;

import de.rub.nds.sshattacker.core.constants.SftpExtension;
import de.rub.nds.sshattacker.core.data.sftp.message.extension.SftpExtensionCheckFile;
import de.rub.nds.sshattacker.core.data.sftp.parser.extension.SftpExtensionWithVersionParser;
import de.rub.nds.sshattacker.core.data.sftp.preperator.extension.SftpExtensionWithVersionPreparator;
import de.rub.nds.sshattacker.core.data.sftp.serializer.extension.SftpExtensionWithVersionSerializer;
import de.rub.nds.sshattacker.core.state.SshContext;

public class SftpExtensionCheckFileHandler
        extends SftpAbstractExtensionHandler<SftpExtensionCheckFile> {

    @Override
    public void adjustContext(SshContext context, SftpExtensionCheckFile object) {}

    @Override
    public SftpExtensionWithVersionParser<SftpExtensionCheckFile> getParser(
            byte[] array, SshContext context) {
        return new SftpExtensionWithVersionParser<>(SftpExtensionCheckFile::new, array);
    }

    public SftpExtensionWithVersionParser<SftpExtensionCheckFile> getParser(
            byte[] array, int startPosition, SshContext context) {
        return new SftpExtensionWithVersionParser<>(
                SftpExtensionCheckFile::new, array, startPosition);
    }

    public static final SftpExtensionWithVersionPreparator<SftpExtensionCheckFile> PREPARATOR =
            new SftpExtensionWithVersionPreparator<>(SftpExtension.CHECK_FILE);

    public static final SftpExtensionWithVersionSerializer<SftpExtensionCheckFile> SERIALIZER =
            new SftpExtensionWithVersionSerializer<>();
}
