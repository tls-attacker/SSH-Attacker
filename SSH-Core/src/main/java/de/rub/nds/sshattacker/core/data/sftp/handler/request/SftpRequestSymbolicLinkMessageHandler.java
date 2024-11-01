/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.handler.request;

import de.rub.nds.sshattacker.core.data.sftp.*;
import de.rub.nds.sshattacker.core.data.sftp.message.request.SftpRequestSymbolicLinkMessage;
import de.rub.nds.sshattacker.core.data.sftp.parser.request.SftpRequestSymbolicLinkMessageParser;
import de.rub.nds.sshattacker.core.data.sftp.preperator.request.SftpRequestSymbolicLinkMessagePreparator;
import de.rub.nds.sshattacker.core.data.sftp.serializer.request.SftpRequestSymbolicLinkMessageSerializer;
import de.rub.nds.sshattacker.core.state.SshContext;

public class SftpRequestSymbolicLinkMessageHandler
        extends SftpMessageHandler<SftpRequestSymbolicLinkMessage> {

    public SftpRequestSymbolicLinkMessageHandler(SshContext context) {
        super(context);
    }

    public SftpRequestSymbolicLinkMessageHandler(
            SshContext context, SftpRequestSymbolicLinkMessage message) {
        super(context, message);
    }

    @Override
    public void adjustContext() {
        // TODO: Handle SftpRequestSymbolicLinkMessage
    }

    @Override
    public SftpRequestSymbolicLinkMessageParser getParser(byte[] array) {
        return new SftpRequestSymbolicLinkMessageParser(array);
    }

    @Override
    public SftpRequestSymbolicLinkMessageParser getParser(byte[] array, int startPosition) {
        return new SftpRequestSymbolicLinkMessageParser(array, startPosition);
    }

    @Override
    public SftpRequestSymbolicLinkMessagePreparator getPreparator() {
        return new SftpRequestSymbolicLinkMessagePreparator(context.getChooser(), message);
    }

    @Override
    public SftpRequestSymbolicLinkMessageSerializer getSerializer() {
        return new SftpRequestSymbolicLinkMessageSerializer(message);
    }
}
