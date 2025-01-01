/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.handler.request;

import de.rub.nds.sshattacker.core.data.sftp.message.request.SftpRequestMakeDirMessage;
import de.rub.nds.sshattacker.core.data.sftp.parser.request.SftpRequestMakeDirMessageParser;
import de.rub.nds.sshattacker.core.data.sftp.preperator.request.SftpRequestMakeDirMessagePreparator;
import de.rub.nds.sshattacker.core.data.sftp.serializer.request.SftpRequestMakeDirMessageSerializer;
import de.rub.nds.sshattacker.core.state.SshContext;

public class SftpRequestMakeDirMessageHandler
        extends SftpRequestMessageHandler<SftpRequestMakeDirMessage> {

    @Override
    public SftpRequestMakeDirMessageParser getParser(byte[] array, SshContext context) {
        return new SftpRequestMakeDirMessageParser(array, context.getChooser());
    }

    @Override
    public SftpRequestMakeDirMessageParser getParser(
            byte[] array, int startPosition, SshContext context) {
        return new SftpRequestMakeDirMessageParser(array, startPosition, context.getChooser());
    }

    public static final SftpRequestMakeDirMessagePreparator PREPARATOR =
            new SftpRequestMakeDirMessagePreparator();

    public static final SftpRequestMakeDirMessageSerializer SERIALIZER =
            new SftpRequestMakeDirMessageSerializer();
}
