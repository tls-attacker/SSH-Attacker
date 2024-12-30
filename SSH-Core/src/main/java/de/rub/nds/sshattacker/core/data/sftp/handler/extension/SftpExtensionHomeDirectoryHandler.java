/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.handler.extension;

import de.rub.nds.sshattacker.core.constants.SftpExtension;
import de.rub.nds.sshattacker.core.data.sftp.message.extension.SftpExtensionHomeDirectory;
import de.rub.nds.sshattacker.core.data.sftp.parser.extension.SftpExtensionWithVersionParser;
import de.rub.nds.sshattacker.core.data.sftp.preperator.extension.SftpExtensionWithVersionPreparator;
import de.rub.nds.sshattacker.core.data.sftp.serializer.extension.SftpExtensionWithVersionSerializer;
import de.rub.nds.sshattacker.core.state.SshContext;

public class SftpExtensionHomeDirectoryHandler
        extends SftpAbstractExtensionHandler<SftpExtensionHomeDirectory> {

    public SftpExtensionHomeDirectoryHandler(SshContext context) {
        super(context);
    }

    public SftpExtensionHomeDirectoryHandler(
            SshContext context, SftpExtensionHomeDirectory extension) {
        super(context, extension);
    }

    @Override
    public void adjustContext() {}

    @Override
    public SftpExtensionWithVersionParser<SftpExtensionHomeDirectory> getParser(byte[] array) {
        return new SftpExtensionWithVersionParser<>(SftpExtensionHomeDirectory::new, array);
    }

    @Override
    public SftpExtensionWithVersionParser<SftpExtensionHomeDirectory> getParser(
            byte[] array, int startPosition) {
        return new SftpExtensionWithVersionParser<>(
                SftpExtensionHomeDirectory::new, array, startPosition);
    }

    public static final SftpExtensionWithVersionPreparator<SftpExtensionHomeDirectory> PREPARATOR =
            new SftpExtensionWithVersionPreparator<>(SftpExtension.HOME_DIRECTORY);

    public static final SftpExtensionWithVersionSerializer<SftpExtensionHomeDirectory> SERIALIZER =
            new SftpExtensionWithVersionSerializer<>();
}
