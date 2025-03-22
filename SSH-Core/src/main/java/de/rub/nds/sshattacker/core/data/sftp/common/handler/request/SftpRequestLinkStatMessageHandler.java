/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.common.handler.request;

import de.rub.nds.sshattacker.core.data.sftp.common.message.request.SftpRequestLinkStatMessage;
import de.rub.nds.sshattacker.core.data.sftp.common.parser.request.SftpRequestLinkStatMessageParser;
import de.rub.nds.sshattacker.core.data.sftp.common.preparator.request.SftpRequestLinkStatMessagePreparator;
import de.rub.nds.sshattacker.core.data.sftp.common.serializer.request.SftpRequestLinkStatMessageSerializer;
import de.rub.nds.sshattacker.core.state.SshContext;

public class SftpRequestLinkStatMessageHandler
        extends SftpRequestMessageHandler<SftpRequestLinkStatMessage> {

    @Override
    public SftpRequestLinkStatMessageParser getParser(byte[] array, SshContext context) {
        return new SftpRequestLinkStatMessageParser(array);
    }

    @Override
    public SftpRequestLinkStatMessageParser getParser(
            byte[] array, int startPosition, SshContext context) {
        return new SftpRequestLinkStatMessageParser(array, startPosition);
    }

    public static final SftpRequestLinkStatMessagePreparator PREPARATOR =
            new SftpRequestLinkStatMessagePreparator();

    public static final SftpRequestLinkStatMessageSerializer SERIALIZER =
            new SftpRequestLinkStatMessageSerializer();
}
