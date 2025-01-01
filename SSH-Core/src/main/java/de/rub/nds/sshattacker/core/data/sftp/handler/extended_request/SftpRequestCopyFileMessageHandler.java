/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.handler.extended_request;

import de.rub.nds.sshattacker.core.data.sftp.handler.request.SftpRequestMessageHandler;
import de.rub.nds.sshattacker.core.data.sftp.message.extended_request.SftpRequestCopyFileMessage;
import de.rub.nds.sshattacker.core.data.sftp.parser.extended_request.SftpRequestCopyFileMessageParser;
import de.rub.nds.sshattacker.core.data.sftp.preperator.extended_request.SftpRequestCopyFileMessagePreparator;
import de.rub.nds.sshattacker.core.data.sftp.serializer.extended_request.SftpRequestCopyFileMessageSerializer;
import de.rub.nds.sshattacker.core.state.SshContext;

public class SftpRequestCopyFileMessageHandler
        extends SftpRequestMessageHandler<SftpRequestCopyFileMessage> {

    @Override
    public SftpRequestCopyFileMessageParser getParser(byte[] array, SshContext context) {
        return new SftpRequestCopyFileMessageParser(array);
    }

    @Override
    public SftpRequestCopyFileMessageParser getParser(
            byte[] array, int startPosition, SshContext context) {
        return new SftpRequestCopyFileMessageParser(array, startPosition);
    }

    public static final SftpRequestCopyFileMessagePreparator PREPARATOR =
            new SftpRequestCopyFileMessagePreparator();

    public static final SftpRequestCopyFileMessageSerializer SERIALIZER =
            new SftpRequestCopyFileMessageSerializer();
}
