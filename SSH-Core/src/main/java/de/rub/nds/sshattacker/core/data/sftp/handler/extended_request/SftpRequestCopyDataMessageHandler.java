/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.handler.extended_request;

import de.rub.nds.sshattacker.core.data.sftp.*;
import de.rub.nds.sshattacker.core.data.sftp.message.extended_request.SftpRequestCopyDataMessage;
import de.rub.nds.sshattacker.core.data.sftp.parser.extended_request.SftpRequestCopyDataMessageParser;
import de.rub.nds.sshattacker.core.data.sftp.preperator.extended_request.SftpRequestCopyDataMessagePreparator;
import de.rub.nds.sshattacker.core.data.sftp.serializer.extended_request.SftpRequestCopyDataMessageSerializer;
import de.rub.nds.sshattacker.core.state.SshContext;

public class SftpRequestCopyDataMessageHandler
        extends SftpMessageHandler<SftpRequestCopyDataMessage> {

    public SftpRequestCopyDataMessageHandler(SshContext context) {
        super(context);
    }

    public SftpRequestCopyDataMessageHandler(
            SshContext context, SftpRequestCopyDataMessage message) {
        super(context, message);
    }

    @Override
    public void adjustContext() {
        // TODO: Handle SftpRequestCopyDataMessage
    }

    @Override
    public SftpRequestCopyDataMessageParser getParser(byte[] array) {
        return new SftpRequestCopyDataMessageParser(array);
    }

    @Override
    public SftpRequestCopyDataMessageParser getParser(byte[] array, int startPosition) {
        return new SftpRequestCopyDataMessageParser(array, startPosition);
    }

    @Override
    public SftpRequestCopyDataMessagePreparator getPreparator() {
        return new SftpRequestCopyDataMessagePreparator(context.getChooser(), message);
    }

    @Override
    public SftpRequestCopyDataMessageSerializer getSerializer() {
        return new SftpRequestCopyDataMessageSerializer(message);
    }
}
