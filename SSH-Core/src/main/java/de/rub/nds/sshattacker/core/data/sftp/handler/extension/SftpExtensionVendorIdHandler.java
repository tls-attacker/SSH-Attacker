/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.handler.extension;

import de.rub.nds.sshattacker.core.data.sftp.message.extension.SftpExtensionVendorId;
import de.rub.nds.sshattacker.core.data.sftp.parser.extension.SftpExtensionVendorIdParser;
import de.rub.nds.sshattacker.core.data.sftp.preperator.extension.SftpExtensionVendorIdPreparator;
import de.rub.nds.sshattacker.core.data.sftp.serializer.extension.SftpExtensionVendorIdSerializer;
import de.rub.nds.sshattacker.core.state.SshContext;

public class SftpExtensionVendorIdHandler
        extends SftpAbstractExtensionHandler<SftpExtensionVendorId> {

    public SftpExtensionVendorIdHandler(SshContext context) {
        super(context);
    }

    public SftpExtensionVendorIdHandler(SshContext context, SftpExtensionVendorId extension) {
        super(context, extension);
    }

    @Override
    public void adjustContext() {
        // TODO: Handle SftpUnknownExtension
    }

    @Override
    public SftpExtensionVendorIdParser getParser(byte[] array) {
        return new SftpExtensionVendorIdParser(array);
    }

    @Override
    public SftpExtensionVendorIdParser getParser(byte[] array, int startPosition) {
        return new SftpExtensionVendorIdParser(array, startPosition);
    }

    @Override
    public SftpExtensionVendorIdPreparator getPreparator() {
        return new SftpExtensionVendorIdPreparator(context.getChooser(), extension);
    }

    @Override
    public SftpExtensionVendorIdSerializer getSerializer() {
        return new SftpExtensionVendorIdSerializer(extension);
    }
}
