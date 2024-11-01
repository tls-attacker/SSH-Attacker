/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.handler.extension;

import de.rub.nds.sshattacker.core.data.sftp.message.extension.SftpExtensionUnknown;
import de.rub.nds.sshattacker.core.data.sftp.parser.extension.SftpExtensionUnknownParser;
import de.rub.nds.sshattacker.core.data.sftp.preperator.extension.SftpExtensionUnknownPreparator;
import de.rub.nds.sshattacker.core.data.sftp.serializer.extension.SftpExtensionUnknownSerializer;
import de.rub.nds.sshattacker.core.state.SshContext;

public class SftpExtensionUnknownHandler
        extends SftpAbstractExtensionHandler<SftpExtensionUnknown> {

    public SftpExtensionUnknownHandler(SshContext context) {
        super(context);
    }

    public SftpExtensionUnknownHandler(SshContext context, SftpExtensionUnknown extension) {
        super(context, extension);
    }

    @Override
    public void adjustContext() {
        // TODO: Handle SftpUnknownExtension
    }

    @Override
    public SftpExtensionUnknownParser getParser(byte[] array) {
        return new SftpExtensionUnknownParser(array);
    }

    @Override
    public SftpExtensionUnknownParser getParser(byte[] array, int startPosition) {
        return new SftpExtensionUnknownParser(array, startPosition);
    }

    @Override
    public SftpExtensionUnknownPreparator getPreparator() {
        return new SftpExtensionUnknownPreparator(context.getChooser(), extension);
    }

    @Override
    public SftpExtensionUnknownSerializer getSerializer() {
        return new SftpExtensionUnknownSerializer(extension);
    }
}
