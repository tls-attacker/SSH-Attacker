/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.common.handler.request;

import de.rub.nds.sshattacker.core.data.sftp.common.message.request.SftpRequestReadMessage;
import de.rub.nds.sshattacker.core.data.sftp.common.parser.request.SftpRequestReadMessageParser;
import de.rub.nds.sshattacker.core.data.sftp.common.preperator.request.SftpRequestReadMessagePreparator;
import de.rub.nds.sshattacker.core.data.sftp.common.serializer.request.SftpRequestReadMessageSerializer;
import de.rub.nds.sshattacker.core.state.SshContext;

public class SftpRequestReadMessageHandler
        extends SftpRequestMessageHandler<SftpRequestReadMessage> {

    @Override
    public SftpRequestReadMessageParser getParser(byte[] array, SshContext context) {
        return new SftpRequestReadMessageParser(array);
    }

    @Override
    public SftpRequestReadMessageParser getParser(
            byte[] array, int startPosition, SshContext context) {
        return new SftpRequestReadMessageParser(array, startPosition);
    }

    public static final SftpRequestReadMessagePreparator PREPARATOR =
            new SftpRequestReadMessagePreparator();

    public static final SftpRequestReadMessageSerializer SERIALIZER =
            new SftpRequestReadMessageSerializer();
}
