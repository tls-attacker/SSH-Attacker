/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.v4.handler.request;

import de.rub.nds.sshattacker.core.data.sftp.common.handler.request.SftpRequestMessageHandler;
import de.rub.nds.sshattacker.core.data.sftp.v4.message.request.SftpV4RequestOpenMessage;
import de.rub.nds.sshattacker.core.data.sftp.v4.parser.request.SftpV4RequestOpenMessageParser;
import de.rub.nds.sshattacker.core.data.sftp.v4.preperator.request.SftpV4RequestOpenMessagePreparator;
import de.rub.nds.sshattacker.core.data.sftp.v4.serializer.request.SftpV4RequestOpenMessageSerializer;
import de.rub.nds.sshattacker.core.state.SshContext;

public class SftpV4RequestOpenMessageHandler
        extends SftpRequestMessageHandler<SftpV4RequestOpenMessage> {

    @Override
    public SftpV4RequestOpenMessageParser getParser(byte[] array, SshContext context) {
        return new SftpV4RequestOpenMessageParser(array);
    }

    @Override
    public SftpV4RequestOpenMessageParser getParser(
            byte[] array, int startPosition, SshContext context) {
        return new SftpV4RequestOpenMessageParser(array, startPosition);
    }

    public static final SftpV4RequestOpenMessagePreparator PREPARATOR =
            new SftpV4RequestOpenMessagePreparator();

    public static final SftpV4RequestOpenMessageSerializer SERIALIZER =
            new SftpV4RequestOpenMessageSerializer();
}
