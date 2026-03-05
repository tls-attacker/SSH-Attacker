/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.v4.handler.request;

import de.rub.nds.sshattacker.core.data.sftp.common.handler.request.SftpRequestMessageHandler;
import de.rub.nds.sshattacker.core.data.sftp.v4.message.request.SftpV4RequestMakeDirMessage;
import de.rub.nds.sshattacker.core.data.sftp.v4.parser.request.SftpV4RequestMakeDirMessageParser;
import de.rub.nds.sshattacker.core.data.sftp.v4.preparator.request.SftpV4RequestMakeDirMessagePreparator;
import de.rub.nds.sshattacker.core.data.sftp.v4.serializer.request.SftpV4RequestMakeDirMessageSerializer;
import de.rub.nds.sshattacker.core.state.SshContext;

public class SftpV4RequestMakeDirMessageHandler
        extends SftpRequestMessageHandler<SftpV4RequestMakeDirMessage> {

    @Override
    public SftpV4RequestMakeDirMessageParser getParser(byte[] array, SshContext context) {
        return new SftpV4RequestMakeDirMessageParser(array);
    }

    @Override
    public SftpV4RequestMakeDirMessageParser getParser(
            byte[] array, int startPosition, SshContext context) {
        return new SftpV4RequestMakeDirMessageParser(array, startPosition);
    }

    public static final SftpV4RequestMakeDirMessagePreparator PREPARATOR =
            new SftpV4RequestMakeDirMessagePreparator();

    public static final SftpV4RequestMakeDirMessageSerializer SERIALIZER =
            new SftpV4RequestMakeDirMessageSerializer();
}
