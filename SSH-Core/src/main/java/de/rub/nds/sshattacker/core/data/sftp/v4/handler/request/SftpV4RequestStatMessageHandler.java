/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.v4.handler.request;

import de.rub.nds.sshattacker.core.data.sftp.common.handler.request.SftpRequestMessageHandler;
import de.rub.nds.sshattacker.core.data.sftp.v4.message.request.SftpV4RequestStatMessage;
import de.rub.nds.sshattacker.core.data.sftp.v4.parser.request.SftpV4RequestStatMessageParser;
import de.rub.nds.sshattacker.core.data.sftp.v4.preperator.request.SftpV4RequestStatMessagePreparator;
import de.rub.nds.sshattacker.core.data.sftp.v4.serializer.request.SftpV4RequestStatMessageSerializer;
import de.rub.nds.sshattacker.core.state.SshContext;

public class SftpV4RequestStatMessageHandler
        extends SftpRequestMessageHandler<SftpV4RequestStatMessage> {

    @Override
    public SftpV4RequestStatMessageParser getParser(byte[] array, SshContext context) {
        return new SftpV4RequestStatMessageParser(array);
    }

    @Override
    public SftpV4RequestStatMessageParser getParser(
            byte[] array, int startPosition, SshContext context) {
        return new SftpV4RequestStatMessageParser(array, startPosition);
    }

    public static final SftpV4RequestStatMessagePreparator PREPARATOR =
            new SftpV4RequestStatMessagePreparator();

    public static final SftpV4RequestStatMessageSerializer SERIALIZER =
            new SftpV4RequestStatMessageSerializer();
}
