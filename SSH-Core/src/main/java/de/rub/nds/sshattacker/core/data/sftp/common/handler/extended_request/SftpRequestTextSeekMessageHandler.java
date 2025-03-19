/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.common.handler.extended_request;

import de.rub.nds.sshattacker.core.data.sftp.common.handler.request.SftpRequestMessageHandler;
import de.rub.nds.sshattacker.core.data.sftp.common.message.extended_request.SftpRequestTextSeekMessage;
import de.rub.nds.sshattacker.core.data.sftp.common.parser.extended_request.SftpRequestTextSeekMessageParser;
import de.rub.nds.sshattacker.core.data.sftp.common.preparator.extended_request.SftpRequestTextSeekMessagePreparator;
import de.rub.nds.sshattacker.core.data.sftp.common.serializer.extended_request.SftpRequestTextSeekMessageSerializer;
import de.rub.nds.sshattacker.core.state.SshContext;

public class SftpRequestTextSeekMessageHandler
        extends SftpRequestMessageHandler<SftpRequestTextSeekMessage> {

    @Override
    public void adjustContext(SshContext context, SftpRequestTextSeekMessage object) {
        // TODO: Handle SftpRequestTextSeekMessage
    }

    @Override
    public SftpRequestTextSeekMessageParser getParser(byte[] array, SshContext context) {
        return new SftpRequestTextSeekMessageParser(array);
    }

    @Override
    public SftpRequestTextSeekMessageParser getParser(
            byte[] array, int startPosition, SshContext context) {
        return new SftpRequestTextSeekMessageParser(array, startPosition);
    }

    public static final SftpRequestTextSeekMessagePreparator PREPARATOR =
            new SftpRequestTextSeekMessagePreparator();

    public static final SftpRequestTextSeekMessageSerializer SERIALIZER =
            new SftpRequestTextSeekMessageSerializer();
}
