/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.common.handler.extended_response;

import de.rub.nds.sshattacker.core.data.sftp.common.handler.response.SftpResponseMessageHandler;
import de.rub.nds.sshattacker.core.data.sftp.common.message.extended_response.SftpResponseStatVfsMessage;
import de.rub.nds.sshattacker.core.data.sftp.common.parser.extended_response.SftpResponseStatVfsMessageParser;
import de.rub.nds.sshattacker.core.data.sftp.common.preparator.extended_response.SftpResponseStatVfsMessagePreparator;
import de.rub.nds.sshattacker.core.data.sftp.common.serializer.extended_response.SftpResponseStatVfsMessageSerializer;
import de.rub.nds.sshattacker.core.state.SshContext;

public class SftpResponseStatVfsMessageHandler
        extends SftpResponseMessageHandler<SftpResponseStatVfsMessage> {

    @Override
    public SftpResponseStatVfsMessageParser getParser(byte[] array, SshContext context) {
        return new SftpResponseStatVfsMessageParser(array);
    }

    @Override
    public SftpResponseStatVfsMessageParser getParser(
            byte[] array, int startPosition, SshContext context) {
        return new SftpResponseStatVfsMessageParser(array, startPosition);
    }

    public static final SftpResponseStatVfsMessagePreparator PREPARATOR =
            new SftpResponseStatVfsMessagePreparator();

    public static final SftpResponseStatVfsMessageSerializer SERIALIZER =
            new SftpResponseStatVfsMessageSerializer();
}
