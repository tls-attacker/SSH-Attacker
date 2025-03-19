/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.v4.handler.request;

import de.rub.nds.sshattacker.core.data.sftp.common.handler.request.SftpRequestMessageHandler;
import de.rub.nds.sshattacker.core.data.sftp.v4.message.request.SftpV4RequestFileSetStatMessage;
import de.rub.nds.sshattacker.core.data.sftp.v4.parser.request.SftpV4RequestFileSetStatMessageParser;
import de.rub.nds.sshattacker.core.data.sftp.v4.preparator.request.SftpV4RequestFileSetStatMessagePreparator;
import de.rub.nds.sshattacker.core.data.sftp.v4.serializer.request.SftpV4RequestFileSetStatMessageSerializer;
import de.rub.nds.sshattacker.core.state.SshContext;

public class SftpV4RequestFileSetStatMessageHandler
        extends SftpRequestMessageHandler<SftpV4RequestFileSetStatMessage> {

    @Override
    public SftpV4RequestFileSetStatMessageParser getParser(byte[] array, SshContext context) {
        return new SftpV4RequestFileSetStatMessageParser(array);
    }

    @Override
    public SftpV4RequestFileSetStatMessageParser getParser(
            byte[] array, int startPosition, SshContext context) {
        return new SftpV4RequestFileSetStatMessageParser(array, startPosition);
    }

    public static final SftpV4RequestFileSetStatMessagePreparator PREPARATOR =
            new SftpV4RequestFileSetStatMessagePreparator();

    public static final SftpV4RequestFileSetStatMessageSerializer SERIALIZER =
            new SftpV4RequestFileSetStatMessageSerializer();
}
