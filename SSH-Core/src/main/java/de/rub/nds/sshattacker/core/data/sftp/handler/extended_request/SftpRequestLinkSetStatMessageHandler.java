/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.handler.extended_request;

import de.rub.nds.sshattacker.core.data.sftp.*;
import de.rub.nds.sshattacker.core.data.sftp.message.extended_request.SftpRequestLinkSetStatMessage;
import de.rub.nds.sshattacker.core.data.sftp.parser.extended_request.SftpRequestLinkSetStatMessageParser;
import de.rub.nds.sshattacker.core.data.sftp.preperator.extended_request.SftpRequestLinkSetStatMessagePreparator;
import de.rub.nds.sshattacker.core.data.sftp.serializer.extended_request.SftpRequestLinkSetStatMessageSerializer;
import de.rub.nds.sshattacker.core.state.SshContext;

public class SftpRequestLinkSetStatMessageHandler
        extends SftpMessageHandler<SftpRequestLinkSetStatMessage> {

    public SftpRequestLinkSetStatMessageHandler(SshContext context) {
        super(context);
    }

    public SftpRequestLinkSetStatMessageHandler(
            SshContext context, SftpRequestLinkSetStatMessage message) {
        super(context, message);
    }

    @Override
    public void adjustContext() {
        // TODO: Handle SftpRequestLinkSetStatMessage
    }

    @Override
    public SftpRequestLinkSetStatMessageParser getParser(byte[] array) {
        return new SftpRequestLinkSetStatMessageParser(array);
    }

    @Override
    public SftpRequestLinkSetStatMessageParser getParser(byte[] array, int startPosition) {
        return new SftpRequestLinkSetStatMessageParser(array, startPosition);
    }

    @Override
    public SftpRequestLinkSetStatMessagePreparator getPreparator() {
        return new SftpRequestLinkSetStatMessagePreparator(context.getChooser(), message);
    }

    @Override
    public SftpRequestLinkSetStatMessageSerializer getSerializer() {
        return new SftpRequestLinkSetStatMessageSerializer(message);
    }
}
