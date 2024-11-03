/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.handler.extended_request;

import de.rub.nds.sshattacker.core.data.sftp.handler.request.SftpRequestMessageHandler;
import de.rub.nds.sshattacker.core.data.sftp.message.extended_request.SftpRequestStatVfsMessage;
import de.rub.nds.sshattacker.core.data.sftp.parser.extended_request.SftpRequestStatVfsMessageParser;
import de.rub.nds.sshattacker.core.data.sftp.preperator.extended_request.SftpRequestStatVfsMessagePreparator;
import de.rub.nds.sshattacker.core.data.sftp.serializer.extended_request.SftpRequestStatVfsMessageSerializer;
import de.rub.nds.sshattacker.core.state.SshContext;

public class SftpRequestStatVfsMessageHandler
        extends SftpRequestMessageHandler<SftpRequestStatVfsMessage> {

    public SftpRequestStatVfsMessageHandler(SshContext context) {
        super(context);
    }

    public SftpRequestStatVfsMessageHandler(SshContext context, SftpRequestStatVfsMessage message) {
        super(context, message);
    }

    @Override
    public SftpRequestStatVfsMessageParser getParser(byte[] array) {
        return new SftpRequestStatVfsMessageParser(array);
    }

    @Override
    public SftpRequestStatVfsMessageParser getParser(byte[] array, int startPosition) {
        return new SftpRequestStatVfsMessageParser(array, startPosition);
    }

    @Override
    public SftpRequestStatVfsMessagePreparator getPreparator() {
        return new SftpRequestStatVfsMessagePreparator(context.getChooser(), message);
    }

    @Override
    public SftpRequestStatVfsMessageSerializer getSerializer() {
        return new SftpRequestStatVfsMessageSerializer(message);
    }
}
