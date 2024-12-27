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

    public SftpExtensionHardlinkHandler(SshContext context) {
        super(context);
    }

    public SftpExtensionHardlinkHandler(SshContext context, SftpExtensionHardlink extension) {
        super(context, extension);
    }

    @Override
    public void adjustContext() {
        // TODO: Handle SftpUnknownExtension
    }

    @Override
    public SftpExtensionWithVersionParser<SftpExtensionHardlink> getParser(byte[] array) {
        return new SftpExtensionWithVersionParser<>(SftpExtensionHardlink::new, array);
    }

    @Override
    public SftpExtensionWithVersionParser<SftpExtensionHardlink> getParser(
            byte[] array, int startPosition) {
        return new SftpExtensionWithVersionParser<>(
                SftpExtensionHardlink::new, array, startPosition);
    }

    public static final SftpExtensionWithVersionPreparator<SftpExtensionHardlink> PREPARATOR =
            new SftpExtensionWithVersionPreparator<>(SftpExtension.HARDLINK_OPENSSH_COM);

    @Override
    public SftpExtensionWithVersionSerializer<SftpExtensionHardlink> getSerializer() {
        return new SftpExtensionWithVersionSerializer<>(extension);
    }
}
