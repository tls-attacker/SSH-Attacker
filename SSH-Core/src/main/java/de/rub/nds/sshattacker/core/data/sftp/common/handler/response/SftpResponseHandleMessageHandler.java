/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.common.handler.response;

import de.rub.nds.sshattacker.core.data.sftp.common.message.response.SftpResponseHandleMessage;
import de.rub.nds.sshattacker.core.data.sftp.common.parser.response.SftpResponseHandleMessageParser;
import de.rub.nds.sshattacker.core.data.sftp.common.preperator.response.SftpResponseHandleMessagePreparator;
import de.rub.nds.sshattacker.core.data.sftp.common.serializer.response.SftpResponseHandleMessageSerializer;
import de.rub.nds.sshattacker.core.state.SshContext;

public class SftpResponseHandleMessageHandler
        extends SftpResponseMessageHandler<SftpResponseHandleMessage> {

    @Override
    public void adjustContext(SshContext context, SftpResponseHandleMessage object) {
        context.getSftpManager().addHandle(object);
        super.adjustContext(context, object);
    }

    @Override
    public SftpResponseHandleMessageParser getParser(byte[] array, SshContext context) {
        return new SftpResponseHandleMessageParser(array);
    }

    @Override
    public SftpResponseHandleMessageParser getParser(
            byte[] array, int startPosition, SshContext context) {
        return new SftpResponseHandleMessageParser(array, startPosition);
    }

    public static final SftpResponseHandleMessagePreparator PREPARATOR =
            new SftpResponseHandleMessagePreparator();

    public static final SftpResponseHandleMessageSerializer SERIALIZER =
            new SftpResponseHandleMessageSerializer();
}
