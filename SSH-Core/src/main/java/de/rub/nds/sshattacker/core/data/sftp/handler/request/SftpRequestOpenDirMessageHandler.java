/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.handler.request;

import de.rub.nds.sshattacker.core.data.sftp.message.request.SftpRequestOpenDirMessage;
import de.rub.nds.sshattacker.core.data.sftp.parser.request.SftpRequestOpenDirMessageParser;
import de.rub.nds.sshattacker.core.data.sftp.preperator.request.SftpRequestOpenDirMessagePreparator;
import de.rub.nds.sshattacker.core.data.sftp.serializer.request.SftpRequestOpenDirMessageSerializer;
import de.rub.nds.sshattacker.core.state.SshContext;

public class SftpRequestOpenDirMessageHandler
        extends SftpRequestMessageHandler<SftpRequestOpenDirMessage> {

    public SftpRequestOpenDirMessageHandler(SshContext context) {
        super(context);
    }

    public SftpRequestOpenDirMessageHandler(SshContext context, SftpRequestOpenDirMessage message) {
        super(context, message);
    }

    @Override
    public SftpRequestOpenDirMessageParser getParser(byte[] array) {
        return new SftpRequestOpenDirMessageParser(array);
    }

    @Override
    public SftpRequestOpenDirMessageParser getParser(byte[] array, int startPosition) {
        return new SftpRequestOpenDirMessageParser(array, startPosition);
    }

    public static final SftpRequestOpenDirMessagePreparator PREPARATOR =
            new SftpRequestOpenDirMessagePreparator();

    public static final SftpRequestOpenDirMessageSerializer SERIALIZER =
            new SftpRequestOpenDirMessageSerializer();
}
