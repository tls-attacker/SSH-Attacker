/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.handler.request;

import de.rub.nds.sshattacker.core.data.sftp.*;
import de.rub.nds.sshattacker.core.data.sftp.message.request.SftpRequestSetStatMessage;
import de.rub.nds.sshattacker.core.data.sftp.parser.request.SftpRequestSetStatMessageParser;
import de.rub.nds.sshattacker.core.data.sftp.preperator.request.SftpRequestSetStatMessagePreparator;
import de.rub.nds.sshattacker.core.data.sftp.serializer.request.SftpRequestSetStatMessageSerializer;
import de.rub.nds.sshattacker.core.state.SshContext;

public class SftpRequestSetStatMessageHandler
        extends SftpRequestMessageHandler<SftpRequestSetStatMessage> {

    public SftpRequestSetStatMessageHandler(SshContext context) {
        super(context);
    }

    public SftpRequestSetStatMessageHandler(SshContext context, SftpRequestSetStatMessage message) {
        super(context, message);
    }

    @Override
    public SftpRequestSetStatMessageParser getParser(byte[] array) {
        return new SftpRequestSetStatMessageParser(array, context.getChooser());
    }

    @Override
    public SftpRequestSetStatMessageParser getParser(byte[] array, int startPosition) {
        return new SftpRequestSetStatMessageParser(array, startPosition, context.getChooser());
    }

    @Override
    public SftpRequestSetStatMessagePreparator getPreparator() {
        return new SftpRequestSetStatMessagePreparator(context.getChooser(), message);
    }

    @Override
    public SftpRequestSetStatMessageSerializer getSerializer() {
        return new SftpRequestSetStatMessageSerializer(message);
    }
}
