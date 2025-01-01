/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.handler.response;

import de.rub.nds.sshattacker.core.data.sftp.message.response.SftpResponseNameMessage;
import de.rub.nds.sshattacker.core.data.sftp.parser.response.SftpResponseNameMessageParser;
import de.rub.nds.sshattacker.core.data.sftp.preperator.response.SftpResponseNameMessagePreparator;
import de.rub.nds.sshattacker.core.data.sftp.serializer.response.SftpResponseNameMessageSerializer;
import de.rub.nds.sshattacker.core.state.SshContext;

public class SftpResponseNameMessageHandler
        extends SftpResponseMessageHandler<SftpResponseNameMessage> {

    @Override
    public SftpResponseNameMessageParser getParser(byte[] array, SshContext context) {
        return new SftpResponseNameMessageParser(array, context.getChooser());
    }

    @Override
    public SftpResponseNameMessageParser getParser(
            byte[] array, int startPosition, SshContext context) {
        return new SftpResponseNameMessageParser(array, startPosition, context.getChooser());
    }

    public static final SftpResponseNameMessagePreparator PREPARATOR =
            new SftpResponseNameMessagePreparator();

    public static final SftpResponseNameMessageSerializer SERIALIZER =
            new SftpResponseNameMessageSerializer();
}
