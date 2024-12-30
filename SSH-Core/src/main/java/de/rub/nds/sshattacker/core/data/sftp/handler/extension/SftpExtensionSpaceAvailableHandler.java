/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.handler.extension;

import de.rub.nds.sshattacker.core.constants.SftpExtension;
import de.rub.nds.sshattacker.core.data.sftp.message.extension.SftpExtensionSpaceAvailable;
import de.rub.nds.sshattacker.core.data.sftp.parser.extension.SftpExtensionWithVersionParser;
import de.rub.nds.sshattacker.core.data.sftp.preperator.extension.SftpExtensionWithVersionPreparator;
import de.rub.nds.sshattacker.core.data.sftp.serializer.extension.SftpExtensionWithVersionSerializer;
import de.rub.nds.sshattacker.core.state.SshContext;

public class SftpExtensionSpaceAvailableHandler
        extends SftpAbstractExtensionHandler<SftpExtensionSpaceAvailable> {

    public SftpExtensionSpaceAvailableHandler(SshContext context) {
        super(context);
    }

    public SftpExtensionSpaceAvailableHandler(
            SshContext context, SftpExtensionSpaceAvailable extension) {
        super(context, extension);
    }

    @Override
    public void adjustContext() {}

    @Override
    public SftpExtensionWithVersionParser<SftpExtensionSpaceAvailable> getParser(byte[] array) {
        return new SftpExtensionWithVersionParser<>(SftpExtensionSpaceAvailable::new, array);
    }

    @Override
    public SftpExtensionWithVersionParser<SftpExtensionSpaceAvailable> getParser(
            byte[] array, int startPosition) {
        return new SftpExtensionWithVersionParser<>(
                SftpExtensionSpaceAvailable::new, array, startPosition);
    }

    public static final SftpExtensionWithVersionPreparator<SftpExtensionSpaceAvailable> PREPARATOR =
            new SftpExtensionWithVersionPreparator<>(SftpExtension.SPACE_AVAILABLE);

    public static final SftpExtensionWithVersionSerializer<SftpExtensionSpaceAvailable> SERIALIZER =
            new SftpExtensionWithVersionSerializer<>();
}
