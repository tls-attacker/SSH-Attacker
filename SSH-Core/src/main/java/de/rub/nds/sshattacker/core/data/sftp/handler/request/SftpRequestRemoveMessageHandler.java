/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.handler.request;

import de.rub.nds.sshattacker.core.data.sftp.message.request.SftpRequestRemoveMessage;
import de.rub.nds.sshattacker.core.data.sftp.parser.request.SftpRequestRemoveMessageParser;
import de.rub.nds.sshattacker.core.data.sftp.preperator.request.SftpRequestRemoveMessagePreparator;
import de.rub.nds.sshattacker.core.data.sftp.serializer.request.SftpRequestRemoveMessageSerializer;
import de.rub.nds.sshattacker.core.state.SshContext;

public class SftpRequestRemoveMessageHandler
        extends SftpRequestMessageHandler<SftpRequestRemoveMessage> {

    @Override
    public SftpRequestRemoveMessageParser getParser(byte[] array, SshContext context) {
        return new SftpRequestRemoveMessageParser(array);
    }

    @Override
    public SftpRequestRemoveMessageParser getParser(
            byte[] array, int startPosition, SshContext context) {
        return new SftpRequestRemoveMessageParser(array, startPosition);
    }

    public static final SftpRequestRemoveMessagePreparator PREPARATOR =
            new SftpRequestRemoveMessagePreparator();

    public static final SftpRequestRemoveMessageSerializer SERIALIZER =
            new SftpRequestRemoveMessageSerializer();
}
