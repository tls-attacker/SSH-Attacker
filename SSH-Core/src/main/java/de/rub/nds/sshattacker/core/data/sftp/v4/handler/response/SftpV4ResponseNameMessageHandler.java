/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.v4.handler.response;

import de.rub.nds.sshattacker.core.data.sftp.common.handler.response.SftpResponseMessageHandler;
import de.rub.nds.sshattacker.core.data.sftp.v4.message.response.SftpV4ResponseNameMessage;
import de.rub.nds.sshattacker.core.data.sftp.v4.parser.response.SftpV4ResponseNameMessageParser;
import de.rub.nds.sshattacker.core.data.sftp.v4.preparator.response.SftpV4ResponseNameMessagePreparator;
import de.rub.nds.sshattacker.core.data.sftp.v4.serializer.response.SftpV4ResponseNameMessageSerializer;
import de.rub.nds.sshattacker.core.state.SshContext;

public class SftpV4ResponseNameMessageHandler
        extends SftpResponseMessageHandler<SftpV4ResponseNameMessage> {

    @Override
    public SftpV4ResponseNameMessageParser getParser(byte[] array, SshContext context) {
        return new SftpV4ResponseNameMessageParser(array);
    }

    @Override
    public SftpV4ResponseNameMessageParser getParser(
            byte[] array, int startPosition, SshContext context) {
        return new SftpV4ResponseNameMessageParser(array, startPosition);
    }

    public static final SftpV4ResponseNameMessagePreparator PREPARATOR =
            new SftpV4ResponseNameMessagePreparator();

    public static final SftpV4ResponseNameMessageSerializer SERIALIZER =
            new SftpV4ResponseNameMessageSerializer();
}
