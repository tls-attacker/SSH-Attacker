/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.handler.extension;

import de.rub.nds.sshattacker.core.constants.SftpExtension;
import de.rub.nds.sshattacker.core.data.sftp.message.extension.SftpExtensionFileSync;
import de.rub.nds.sshattacker.core.data.sftp.parser.extension.SftpExtensionWithVersionParser;
import de.rub.nds.sshattacker.core.data.sftp.preperator.extension.SftpExtensionWithVersionPreparator;
import de.rub.nds.sshattacker.core.data.sftp.serializer.extension.SftpExtensionWithVersionSerializer;
import de.rub.nds.sshattacker.core.state.SshContext;

public class SftpExtensionFileSyncHandler
        extends SftpAbstractExtensionHandler<SftpExtensionFileSync> {

    @Override
    public void adjustContext(SshContext context, SftpExtensionFileSync object) {}

    @Override
    public SftpExtensionWithVersionParser<SftpExtensionFileSync> getParser(
            byte[] array, SshContext context) {
        return new SftpExtensionWithVersionParser<>(SftpExtensionFileSync::new, array);
    }

    @Override
    public SftpExtensionWithVersionParser<SftpExtensionFileSync> getParser(
            byte[] array, int startPosition, SshContext context) {
        return new SftpExtensionWithVersionParser<>(
                SftpExtensionFileSync::new, array, startPosition);
    }

    public static final SftpExtensionWithVersionPreparator<SftpExtensionFileSync> PREPARATOR =
            new SftpExtensionWithVersionPreparator<>(SftpExtension.F_SYNC_OPENSSH_COM);

    public static final SftpExtensionWithVersionSerializer<SftpExtensionFileSync> SERIALIZER =
            new SftpExtensionWithVersionSerializer<>();
}
