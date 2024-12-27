/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.handler.request;

import de.rub.nds.sshattacker.core.data.sftp.message.request.SftpRequestCloseMessage;
import de.rub.nds.sshattacker.core.data.sftp.parser.request.SftpRequestCloseMessageParser;
import de.rub.nds.sshattacker.core.data.sftp.preperator.request.SftpRequestCloseMessagePreparator;
import de.rub.nds.sshattacker.core.data.sftp.serializer.request.SftpRequestCloseMessageSerializer;
import de.rub.nds.sshattacker.core.state.SshContext;

public class SftpRequestCloseMessageHandler
        extends SftpRequestMessageHandler<SftpRequestCloseMessage> {

    public SftpRequestCloseMessageHandler(SshContext context) {
        super(context);
    }

    public SftpRequestCloseMessageHandler(SshContext context, SftpRequestCloseMessage message) {
        super(context, message);
    }

    @Override
    public SftpRequestCloseMessageParser getParser(byte[] array) {
        return new SftpRequestCloseMessageParser(array);
    }

    @Override
    public SftpRequestCloseMessageParser getParser(byte[] array, int startPosition) {
        return new SftpRequestCloseMessageParser(array, startPosition);
    }

    public static final SftpRequestCloseMessagePreparator PREPARATOR =
            new SftpRequestCloseMessagePreparator();

    public static final SftpRequestCloseMessageSerializer SERIALIZER =
            new SftpRequestCloseMessageSerializer();
}
