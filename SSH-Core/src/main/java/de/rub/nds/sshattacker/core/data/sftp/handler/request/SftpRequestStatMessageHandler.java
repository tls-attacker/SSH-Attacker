/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.handler.request;

import de.rub.nds.sshattacker.core.data.sftp.*;
import de.rub.nds.sshattacker.core.data.sftp.message.request.SftpRequestStatMessage;
import de.rub.nds.sshattacker.core.data.sftp.parser.request.SftpRequestStatMessageParser;
import de.rub.nds.sshattacker.core.data.sftp.preperator.request.SftpRequestStatMessagePreparator;
import de.rub.nds.sshattacker.core.data.sftp.serializer.request.SftpRequestStatMessageSerializer;
import de.rub.nds.sshattacker.core.state.SshContext;

public class SftpRequestStatMessageHandler
        extends SftpRequestMessageHandler<SftpRequestStatMessage> {

    public SftpRequestStatMessageHandler(SshContext context) {
        super(context);
    }

    public SftpRequestStatMessageHandler(SshContext context, SftpRequestStatMessage message) {
        super(context, message);
    }

    @Override
    public SftpRequestStatMessageParser getParser(byte[] array) {
        return new SftpRequestStatMessageParser(array, context.getChooser());
    }

    @Override
    public SftpRequestStatMessageParser getParser(byte[] array, int startPosition) {
        return new SftpRequestStatMessageParser(array, startPosition, context.getChooser());
    }

    @Override
    public SftpRequestStatMessagePreparator getPreparator() {
        return new SftpRequestStatMessagePreparator(context.getChooser(), message);
    }

    @Override
    public SftpRequestStatMessageSerializer getSerializer() {
        return new SftpRequestStatMessageSerializer(message);
    }
}
