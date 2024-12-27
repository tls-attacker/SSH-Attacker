/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.handler.request;

import de.rub.nds.sshattacker.core.data.sftp.message.request.SftpRequestReadMessage;
import de.rub.nds.sshattacker.core.data.sftp.parser.request.SftpRequestReadMessageParser;
import de.rub.nds.sshattacker.core.data.sftp.preperator.request.SftpRequestReadMessagePreparator;
import de.rub.nds.sshattacker.core.data.sftp.serializer.request.SftpRequestReadMessageSerializer;
import de.rub.nds.sshattacker.core.state.SshContext;

public class SftpRequestReadMessageHandler
        extends SftpRequestMessageHandler<SftpRequestReadMessage> {

    public SftpRequestReadMessageHandler(SshContext context) {
        super(context);
    }

    public SftpRequestReadMessageHandler(SshContext context, SftpRequestReadMessage message) {
        super(context, message);
    }

    @Override
    public SftpRequestReadMessageParser getParser(byte[] array) {
        return new SftpRequestReadMessageParser(array);
    }

    @Override
    public SftpRequestReadMessageParser getParser(byte[] array, int startPosition) {
        return new SftpRequestReadMessageParser(array, startPosition);
    }

    public static final SftpRequestReadMessagePreparator PREPARATOR =
            new SftpRequestReadMessagePreparator();

    @Override
    public SftpRequestReadMessageSerializer getSerializer() {
        return new SftpRequestReadMessageSerializer(message);
    }
}
