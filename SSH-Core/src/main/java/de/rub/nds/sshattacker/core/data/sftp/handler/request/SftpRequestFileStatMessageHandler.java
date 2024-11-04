/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.handler.request;

import de.rub.nds.sshattacker.core.data.sftp.*;
import de.rub.nds.sshattacker.core.data.sftp.message.request.SftpRequestFileStatMessage;
import de.rub.nds.sshattacker.core.data.sftp.parser.request.SftpRequestFileStatMessageParser;
import de.rub.nds.sshattacker.core.data.sftp.preperator.request.SftpRequestFileStatMessagePreparator;
import de.rub.nds.sshattacker.core.data.sftp.serializer.request.SftpRequestFileStatMessageSerializer;
import de.rub.nds.sshattacker.core.state.SshContext;

public class SftpRequestFileStatMessageHandler
        extends SftpRequestMessageHandler<SftpRequestFileStatMessage> {

    public SftpRequestFileStatMessageHandler(SshContext context) {
        super(context);
    }

    public SftpRequestFileStatMessageHandler(
            SshContext context, SftpRequestFileStatMessage message) {
        super(context, message);
    }

    @Override
    public SftpRequestFileStatMessageParser getParser(byte[] array) {
        return new SftpRequestFileStatMessageParser(array, context.getChooser());
    }

    @Override
    public SftpRequestFileStatMessageParser getParser(byte[] array, int startPosition) {
        return new SftpRequestFileStatMessageParser(array, startPosition, context.getChooser());
    }

    @Override
    public SftpRequestFileStatMessagePreparator getPreparator() {
        return new SftpRequestFileStatMessagePreparator(context.getChooser(), message);
    }

    @Override
    public SftpRequestFileStatMessageSerializer getSerializer() {
        return new SftpRequestFileStatMessageSerializer(message);
    }
}
