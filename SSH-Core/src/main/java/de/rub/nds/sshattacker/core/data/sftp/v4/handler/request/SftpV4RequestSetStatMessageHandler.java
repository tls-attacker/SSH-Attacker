/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.v4.handler.request;

import de.rub.nds.sshattacker.core.data.sftp.common.handler.request.SftpRequestMessageHandler;
import de.rub.nds.sshattacker.core.data.sftp.v4.message.request.SftpV4RequestSetStatMessage;
import de.rub.nds.sshattacker.core.data.sftp.v4.parser.request.SftpV4RequestSetStatMessageParser;
import de.rub.nds.sshattacker.core.data.sftp.v4.preparator.request.SftpV4RequestSetStatMessagePreparator;
import de.rub.nds.sshattacker.core.data.sftp.v4.serializer.request.SftpV4RequestSetStatMessageSerializer;
import de.rub.nds.sshattacker.core.state.SshContext;

public class SftpV4RequestSetStatMessageHandler
        extends SftpRequestMessageHandler<SftpV4RequestSetStatMessage> {

    @Override
    public SftpV4RequestSetStatMessageParser getParser(byte[] array, SshContext context) {
        return new SftpV4RequestSetStatMessageParser(array);
    }

    @Override
    public SftpV4RequestSetStatMessageParser getParser(
            byte[] array, int startPosition, SshContext context) {
        return new SftpV4RequestSetStatMessageParser(array, startPosition);
    }

    public static final SftpV4RequestSetStatMessagePreparator PREPARATOR =
            new SftpV4RequestSetStatMessagePreparator();

    public static final SftpV4RequestSetStatMessageSerializer SERIALIZER =
            new SftpV4RequestSetStatMessageSerializer();
}
