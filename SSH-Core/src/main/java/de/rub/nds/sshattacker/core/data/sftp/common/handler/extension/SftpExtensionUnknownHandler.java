/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.common.handler.extension;

import de.rub.nds.sshattacker.core.data.sftp.common.message.extension.SftpExtensionUnknown;
import de.rub.nds.sshattacker.core.data.sftp.common.parser.extension.SftpExtensionUnknownParser;
import de.rub.nds.sshattacker.core.data.sftp.common.preperator.extension.SftpExtensionUnknownPreparator;
import de.rub.nds.sshattacker.core.data.sftp.common.serializer.extension.SftpExtensionUnknownSerializer;
import de.rub.nds.sshattacker.core.state.SshContext;

public class SftpExtensionUnknownHandler
        extends SftpAbstractExtensionHandler<SftpExtensionUnknown> {

    @Override
    public void adjustContext(SshContext context, SftpExtensionUnknown object) {}

    @Override
    public SftpExtensionUnknownParser getParser(byte[] array, SshContext context) {
        return new SftpExtensionUnknownParser(array);
    }

    @Override
    public SftpExtensionUnknownParser getParser(
            byte[] array, int startPosition, SshContext context) {
        return new SftpExtensionUnknownParser(array, startPosition);
    }

    public static final SftpExtensionUnknownPreparator PREPARATOR =
            new SftpExtensionUnknownPreparator();

    public static final SftpExtensionUnknownSerializer SERIALIZER =
            new SftpExtensionUnknownSerializer();
}
