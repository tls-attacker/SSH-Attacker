/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.handler;

import de.rub.nds.sshattacker.core.data.sftp.*;
import de.rub.nds.sshattacker.core.data.sftp.message.SftpRequestLinkStatMessage;
import de.rub.nds.sshattacker.core.data.sftp.parser.SftpRequestLinkStatMessageParser;
import de.rub.nds.sshattacker.core.data.sftp.preperator.SftpRequestLinkStatMessagePreparator;
import de.rub.nds.sshattacker.core.data.sftp.serializer.SftpRequestLinkStatMessageSerializer;
import de.rub.nds.sshattacker.core.state.SshContext;

public class SftpRequestLinkStatMessageHandler
        extends SftpMessageHandler<SftpRequestLinkStatMessage> {

    public SftpRequestLinkStatMessageHandler(SshContext context) {
        super(context);
    }

    public SftpRequestLinkStatMessageHandler(
            SshContext context, SftpRequestLinkStatMessage message) {
        super(context, message);
    }

    @Override
    public void adjustContext() {
        // TODO: Handle SftpRequestLinkStatMessage
    }

    @Override
    public SftpRequestLinkStatMessageParser getParser(byte[] array) {
        return new SftpRequestLinkStatMessageParser(array);
    }

    @Override
    public SftpRequestLinkStatMessageParser getParser(byte[] array, int startPosition) {
        return new SftpRequestLinkStatMessageParser(array, startPosition);
    }

    @Override
    public SftpRequestLinkStatMessagePreparator getPreparator() {
        return new SftpRequestLinkStatMessagePreparator(context.getChooser(), message);
    }

    @Override
    public SftpRequestLinkStatMessageSerializer getSerializer() {
        return new SftpRequestLinkStatMessageSerializer(message);
    }
}
