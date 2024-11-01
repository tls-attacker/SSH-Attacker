/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.handler.extended;

import de.rub.nds.sshattacker.core.data.sftp.*;
import de.rub.nds.sshattacker.core.data.sftp.message.extended.SftpRequestVendorIdMessage;
import de.rub.nds.sshattacker.core.data.sftp.parser.extended.SftpRequestVendorIdMessageParser;
import de.rub.nds.sshattacker.core.data.sftp.preperator.extended.SftpRequestVendorIdMessagePreparator;
import de.rub.nds.sshattacker.core.data.sftp.serializer.extended.SftpRequestVendorIdMessageSerializer;
import de.rub.nds.sshattacker.core.state.SshContext;

public class SftpRequestVendorIdMessageHandler
        extends SftpMessageHandler<SftpRequestVendorIdMessage> {

    public SftpRequestVendorIdMessageHandler(SshContext context) {
        super(context);
    }

    public SftpRequestVendorIdMessageHandler(
            SshContext context, SftpRequestVendorIdMessage message) {
        super(context, message);
    }

    @Override
    public void adjustContext() {
        // TODO: Handle SftpRequestVendorIdMessage
    }

    @Override
    public SftpRequestVendorIdMessageParser getParser(byte[] array) {
        return new SftpRequestVendorIdMessageParser(array);
    }

    @Override
    public SftpRequestVendorIdMessageParser getParser(byte[] array, int startPosition) {
        return new SftpRequestVendorIdMessageParser(array, startPosition);
    }

    @Override
    public SftpRequestVendorIdMessagePreparator getPreparator() {
        return new SftpRequestVendorIdMessagePreparator(context.getChooser(), message);
    }

    @Override
    public SftpRequestVendorIdMessageSerializer getSerializer() {
        return new SftpRequestVendorIdMessageSerializer(message);
    }
}
