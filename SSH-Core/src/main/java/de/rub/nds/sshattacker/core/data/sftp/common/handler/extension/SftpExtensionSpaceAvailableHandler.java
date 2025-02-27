/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.common.handler.extension;

import de.rub.nds.sshattacker.core.constants.SftpExtension;
import de.rub.nds.sshattacker.core.data.sftp.common.message.extension.SftpExtensionSpaceAvailable;
import de.rub.nds.sshattacker.core.data.sftp.common.parser.extension.SftpExtensionWithVersionParser;
import de.rub.nds.sshattacker.core.data.sftp.common.preperator.extension.SftpExtensionWithVersionPreparator;
import de.rub.nds.sshattacker.core.data.sftp.common.serializer.extension.SftpExtensionWithVersionSerializer;
import de.rub.nds.sshattacker.core.state.SshContext;

public class SftpExtensionSpaceAvailableHandler
        extends SftpAbstractExtensionHandler<SftpExtensionSpaceAvailable> {

    @Override
    public void adjustContext(SshContext context, SftpExtensionSpaceAvailable object) {}

    @Override
    public SftpExtensionWithVersionParser<SftpExtensionSpaceAvailable> getParser(
            byte[] array, SshContext context) {
        return new SftpExtensionWithVersionParser<>(SftpExtensionSpaceAvailable::new, array);
    }

    @Override
    public SftpExtensionWithVersionParser<SftpExtensionSpaceAvailable> getParser(
            byte[] array, int startPosition, SshContext context) {
        return new SftpExtensionWithVersionParser<>(
                SftpExtensionSpaceAvailable::new, array, startPosition);
    }

    public static final SftpExtensionWithVersionPreparator<SftpExtensionSpaceAvailable> PREPARATOR =
            new SftpExtensionWithVersionPreparator<>(SftpExtension.SPACE_AVAILABLE);

    public static final SftpExtensionWithVersionSerializer<SftpExtensionSpaceAvailable> SERIALIZER =
            new SftpExtensionWithVersionSerializer<>();
}
