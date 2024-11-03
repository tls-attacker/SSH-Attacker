/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.handler.request;

import de.rub.nds.sshattacker.core.data.sftp.*;
import de.rub.nds.sshattacker.core.data.sftp.message.request.SftpRequestMakeDirMessage;
import de.rub.nds.sshattacker.core.data.sftp.parser.request.SftpRequestMakeDirMessageParser;
import de.rub.nds.sshattacker.core.data.sftp.preperator.request.SftpRequestMakeDirMessagePreparator;
import de.rub.nds.sshattacker.core.data.sftp.serializer.request.SftpRequestMakeDirMessageSerializer;
import de.rub.nds.sshattacker.core.state.SshContext;

public class SftpRequestMakeDirMessageHandler
        extends SftpRequestMessageHandler<SftpRequestMakeDirMessage> {

    public SftpRequestMakeDirMessageHandler(SshContext context) {
        super(context);
    }

    public SftpRequestMakeDirMessageHandler(SshContext context, SftpRequestMakeDirMessage message) {
        super(context, message);
    }

    @Override
    public SftpRequestMakeDirMessageParser getParser(byte[] array) {
        return new SftpRequestMakeDirMessageParser(array);
    }

    @Override
    public SftpRequestMakeDirMessageParser getParser(byte[] array, int startPosition) {
        return new SftpRequestMakeDirMessageParser(array, startPosition);
    }

    @Override
    public SftpRequestMakeDirMessagePreparator getPreparator() {
        return new SftpRequestMakeDirMessagePreparator(context.getChooser(), message);
    }

    @Override
    public SftpRequestMakeDirMessageSerializer getSerializer() {
        return new SftpRequestMakeDirMessageSerializer(message);
    }
}
