/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.handler.request;

import de.rub.nds.sshattacker.core.data.sftp.message.request.SftpRequestRemoveDirMessage;
import de.rub.nds.sshattacker.core.data.sftp.parser.request.SftpRequestRemoveDirMessageParser;
import de.rub.nds.sshattacker.core.data.sftp.preperator.request.SftpRequestRemoveDirMessagePreparator;
import de.rub.nds.sshattacker.core.data.sftp.serializer.request.SftpRequestRemoveDirMessageSerializer;
import de.rub.nds.sshattacker.core.state.SshContext;

public class SftpRequestRemoveDirMessageHandler
        extends SftpRequestMessageHandler<SftpRequestRemoveDirMessage> {

    public SftpRequestRemoveDirMessageHandler(SshContext context) {
        super(context);
    }

    public SftpRequestRemoveDirMessageHandler(
            SshContext context, SftpRequestRemoveDirMessage message) {
        super(context, message);
    }

    @Override
    public SftpRequestRemoveDirMessageParser getParser(byte[] array) {
        return new SftpRequestRemoveDirMessageParser(array);
    }

    @Override
    public SftpRequestRemoveDirMessageParser getParser(byte[] array, int startPosition) {
        return new SftpRequestRemoveDirMessageParser(array, startPosition);
    }

    public static final SftpRequestRemoveDirMessagePreparator PREPARATOR =
            new SftpRequestRemoveDirMessagePreparator();

    public static final SftpRequestRemoveDirMessageSerializer SERIALIZER =
            new SftpRequestRemoveDirMessageSerializer();
}
