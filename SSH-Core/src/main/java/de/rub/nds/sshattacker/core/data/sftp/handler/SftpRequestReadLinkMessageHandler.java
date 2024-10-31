/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.handler;

import de.rub.nds.sshattacker.core.data.sftp.*;
import de.rub.nds.sshattacker.core.data.sftp.message.SftpRequestReadLinkMessage;
import de.rub.nds.sshattacker.core.data.sftp.parser.SftpRequestReadLinkMessageParser;
import de.rub.nds.sshattacker.core.data.sftp.preperator.SftpRequestReadLinkMessagePreparator;
import de.rub.nds.sshattacker.core.data.sftp.serializer.SftpRequestReadLinkMessageSerializer;
import de.rub.nds.sshattacker.core.state.SshContext;

public class SftpRequestReadLinkMessageHandler
        extends SftpMessageHandler<SftpRequestReadLinkMessage> {

    public SftpRequestReadLinkMessageHandler(SshContext context) {
        super(context);
    }

    public SftpRequestReadLinkMessageHandler(
            SshContext context, SftpRequestReadLinkMessage message) {
        super(context, message);
    }

    @Override
    public void adjustContext() {
        // TODO: Handle SftpRequestReadLinkMessage
    }

    @Override
    public SftpRequestReadLinkMessageParser getParser(byte[] array) {
        return new SftpRequestReadLinkMessageParser(array);
    }

    @Override
    public SftpRequestReadLinkMessageParser getParser(byte[] array, int startPosition) {
        return new SftpRequestReadLinkMessageParser(array, startPosition);
    }

    @Override
    public SftpRequestReadLinkMessagePreparator getPreparator() {
        return new SftpRequestReadLinkMessagePreparator(context.getChooser(), message);
    }

    @Override
    public SftpRequestReadLinkMessageSerializer getSerializer() {
        return new SftpRequestReadLinkMessageSerializer(message);
    }
}
