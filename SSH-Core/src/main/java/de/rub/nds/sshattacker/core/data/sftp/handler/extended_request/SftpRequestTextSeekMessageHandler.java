/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.handler.extended_request;

import de.rub.nds.sshattacker.core.data.sftp.*;
import de.rub.nds.sshattacker.core.data.sftp.message.extended_request.SftpRequestTextSeekMessage;
import de.rub.nds.sshattacker.core.data.sftp.parser.extended_request.SftpRequestTextSeekMessageParser;
import de.rub.nds.sshattacker.core.data.sftp.preperator.extended_request.SftpRequestTextSeekMessagePreparator;
import de.rub.nds.sshattacker.core.data.sftp.serializer.extended_request.SftpRequestTextSeekMessageSerializer;
import de.rub.nds.sshattacker.core.state.SshContext;

public class SftpRequestTextSeekMessageHandler
        extends SftpMessageHandler<SftpRequestTextSeekMessage> {

    public SftpRequestTextSeekMessageHandler(SshContext context) {
        super(context);
    }

    public SftpRequestTextSeekMessageHandler(
            SshContext context, SftpRequestTextSeekMessage message) {
        super(context, message);
    }

    @Override
    public void adjustContext() {
        // TODO: Handle SftpRequestTextSeekMessage
    }

    @Override
    public SftpRequestTextSeekMessageParser getParser(byte[] array) {
        return new SftpRequestTextSeekMessageParser(array);
    }

    @Override
    public SftpRequestTextSeekMessageParser getParser(byte[] array, int startPosition) {
        return new SftpRequestTextSeekMessageParser(array, startPosition);
    }

    @Override
    public SftpRequestTextSeekMessagePreparator getPreparator() {
        return new SftpRequestTextSeekMessagePreparator(context.getChooser(), message);
    }

    @Override
    public SftpRequestTextSeekMessageSerializer getSerializer() {
        return new SftpRequestTextSeekMessageSerializer(message);
    }
}
