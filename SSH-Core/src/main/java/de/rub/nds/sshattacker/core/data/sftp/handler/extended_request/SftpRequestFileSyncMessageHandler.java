/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.handler.extended_request;

import de.rub.nds.sshattacker.core.data.sftp.handler.request.SftpRequestMessageHandler;
import de.rub.nds.sshattacker.core.data.sftp.message.extended_request.SftpRequestFileSyncMessage;
import de.rub.nds.sshattacker.core.data.sftp.parser.extended_request.SftpRequestFileSyncMessageParser;
import de.rub.nds.sshattacker.core.data.sftp.preperator.extended_request.SftpRequestFileSyncMessagePreparator;
import de.rub.nds.sshattacker.core.data.sftp.serializer.extended_request.SftpRequestFileSyncMessageSerializer;
import de.rub.nds.sshattacker.core.state.SshContext;

public class SftpRequestFileSyncMessageHandler
        extends SftpRequestMessageHandler<SftpRequestFileSyncMessage> {

    @Override
    public SftpRequestFileSyncMessageParser getParser(byte[] array, SshContext context) {
        return new SftpRequestFileSyncMessageParser(array);
    }

    @Override
    public SftpRequestFileSyncMessageParser getParser(
            byte[] array, int startPosition, SshContext context) {
        return new SftpRequestFileSyncMessageParser(array, startPosition);
    }

    public static final SftpRequestFileSyncMessagePreparator PREPARATOR =
            new SftpRequestFileSyncMessagePreparator();

    public static final SftpRequestFileSyncMessageSerializer SERIALIZER =
            new SftpRequestFileSyncMessageSerializer();
}
