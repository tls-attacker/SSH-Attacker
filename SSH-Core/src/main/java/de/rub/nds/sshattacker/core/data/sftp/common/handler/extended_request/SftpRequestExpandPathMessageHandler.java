/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.common.handler.extended_request;

import de.rub.nds.sshattacker.core.data.sftp.common.handler.request.SftpRequestMessageHandler;
import de.rub.nds.sshattacker.core.data.sftp.common.message.extended_request.SftpRequestExpandPathMessage;
import de.rub.nds.sshattacker.core.data.sftp.common.parser.extended_request.SftpRequestExpandPathMessageParser;
import de.rub.nds.sshattacker.core.data.sftp.common.preperator.extended_request.SftpRequestExpandPathMessagePreparator;
import de.rub.nds.sshattacker.core.data.sftp.common.serializer.extended_request.SftpRequestExpandPathMessageSerializer;
import de.rub.nds.sshattacker.core.state.SshContext;

public class SftpRequestExpandPathMessageHandler
        extends SftpRequestMessageHandler<SftpRequestExpandPathMessage> {

    @Override
    public SftpRequestExpandPathMessageParser getParser(byte[] array, SshContext context) {
        return new SftpRequestExpandPathMessageParser(array);
    }

    @Override
    public SftpRequestExpandPathMessageParser getParser(
            byte[] array, int startPosition, SshContext context) {
        return new SftpRequestExpandPathMessageParser(array, startPosition);
    }

    public static final SftpRequestExpandPathMessagePreparator PREPARATOR =
            new SftpRequestExpandPathMessagePreparator();

    public static final SftpRequestExpandPathMessageSerializer SERIALIZER =
            new SftpRequestExpandPathMessageSerializer();
}
