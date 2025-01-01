/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.handler.extension;

import de.rub.nds.sshattacker.core.constants.SftpExtension;
import de.rub.nds.sshattacker.core.data.sftp.message.extension.SftpExtensionHardlink;
import de.rub.nds.sshattacker.core.data.sftp.parser.extension.SftpExtensionWithVersionParser;
import de.rub.nds.sshattacker.core.data.sftp.preperator.extension.SftpExtensionWithVersionPreparator;
import de.rub.nds.sshattacker.core.data.sftp.serializer.extension.SftpExtensionWithVersionSerializer;
import de.rub.nds.sshattacker.core.state.SshContext;

public class SftpExtensionHardlinkHandler
        extends SftpAbstractExtensionHandler<SftpExtensionHardlink> {

    @Override
    public void adjustContext(SshContext context, SftpExtensionHardlink object) {}

    @Override
    public SftpExtensionWithVersionParser<SftpExtensionHardlink> getParser(
            byte[] array, SshContext context) {
        return new SftpExtensionWithVersionParser<>(SftpExtensionHardlink::new, array);
    }

    @Override
    public SftpExtensionWithVersionParser<SftpExtensionHardlink> getParser(
            byte[] array, int startPosition, SshContext context) {
        return new SftpExtensionWithVersionParser<>(
                SftpExtensionHardlink::new, array, startPosition);
    }

    public static final SftpExtensionWithVersionPreparator<SftpExtensionHardlink> PREPARATOR =
            new SftpExtensionWithVersionPreparator<>(SftpExtension.HARDLINK_OPENSSH_COM);

    public static final SftpExtensionWithVersionSerializer<SftpExtensionHardlink> SERIALIZER =
            new SftpExtensionWithVersionSerializer<>();
}
