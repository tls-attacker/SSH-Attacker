/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.handler.request;

import de.rub.nds.sshattacker.core.data.sftp.message.request.SftpRequestReadLinkMessage;
import de.rub.nds.sshattacker.core.data.sftp.parser.request.SftpRequestReadLinkMessageParser;
import de.rub.nds.sshattacker.core.data.sftp.preperator.request.SftpRequestReadLinkMessagePreparator;
import de.rub.nds.sshattacker.core.data.sftp.serializer.request.SftpRequestReadLinkMessageSerializer;
import de.rub.nds.sshattacker.core.state.SshContext;

public class SftpRequestReadLinkMessageHandler
        extends SftpRequestMessageHandler<SftpRequestReadLinkMessage> {

    @Override
    public SftpRequestReadLinkMessageParser getParser(byte[] array, SshContext context) {
        return new SftpRequestReadLinkMessageParser(array);
    }

    @Override
    public SftpRequestReadLinkMessageParser getParser(
            byte[] array, int startPosition, SshContext context) {
        return new SftpRequestReadLinkMessageParser(array, startPosition);
    }

    public static final SftpRequestReadLinkMessagePreparator PREPARATOR =
            new SftpRequestReadLinkMessagePreparator();

    public static final SftpRequestReadLinkMessageSerializer SERIALIZER =
            new SftpRequestReadLinkMessageSerializer();
}
