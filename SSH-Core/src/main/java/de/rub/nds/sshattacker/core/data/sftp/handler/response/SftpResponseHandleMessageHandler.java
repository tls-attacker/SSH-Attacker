/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.handler.response;

import de.rub.nds.sshattacker.core.data.sftp.message.response.SftpResponseHandleMessage;
import de.rub.nds.sshattacker.core.data.sftp.parser.response.SftpResponseHandleMessageParser;
import de.rub.nds.sshattacker.core.data.sftp.preperator.response.SftpResponseHandleMessagePreparator;
import de.rub.nds.sshattacker.core.data.sftp.serializer.response.SftpResponseHandleMessageSerializer;
import de.rub.nds.sshattacker.core.state.SshContext;

public class SftpResponseHandleMessageHandler
        extends SftpResponseMessageHandler<SftpResponseHandleMessage> {

    public SftpResponseHandleMessageHandler(SshContext context) {
        super(context);
    }

    public SftpResponseHandleMessageHandler(SshContext context, SftpResponseHandleMessage message) {
        super(context, message);
    }

    @Override
    public void adjustContext() {
        context.getSftpManager().addHandle(message);
        super.adjustContext();
    }

    @Override
    public SftpResponseHandleMessageParser getParser(byte[] array) {
        return new SftpResponseHandleMessageParser(array);
    }

    @Override
    public SftpResponseHandleMessageParser getParser(byte[] array, int startPosition) {
        return new SftpResponseHandleMessageParser(array, startPosition);
    }

    public static final SftpResponseHandleMessagePreparator PREPARATOR =
            new SftpResponseHandleMessagePreparator();

    @Override
    public SftpResponseHandleMessageSerializer getSerializer() {
        return new SftpResponseHandleMessageSerializer(message);
    }
}
