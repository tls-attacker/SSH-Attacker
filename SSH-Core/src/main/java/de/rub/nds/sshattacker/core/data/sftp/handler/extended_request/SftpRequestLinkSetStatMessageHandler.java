/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.handler.extended_request;

import de.rub.nds.sshattacker.core.data.sftp.handler.request.SftpRequestMessageHandler;
import de.rub.nds.sshattacker.core.data.sftp.message.extended_request.SftpRequestLinkSetStatMessage;
import de.rub.nds.sshattacker.core.data.sftp.parser.extended_request.SftpRequestLinkSetStatMessageParser;
import de.rub.nds.sshattacker.core.data.sftp.preperator.extended_request.SftpRequestLinkSetStatMessagePreparator;
import de.rub.nds.sshattacker.core.data.sftp.serializer.extended_request.SftpRequestLinkSetStatMessageSerializer;
import de.rub.nds.sshattacker.core.state.SshContext;

public class SftpRequestLinkSetStatMessageHandler
        extends SftpRequestMessageHandler<SftpRequestLinkSetStatMessage> {

    @Override
    public SftpRequestLinkSetStatMessageParser getParser(byte[] array, SshContext context) {
        return new SftpRequestLinkSetStatMessageParser(array, context.getChooser());
    }

    @Override
    public SftpRequestLinkSetStatMessageParser getParser(
            byte[] array, int startPosition, SshContext context) {
        return new SftpRequestLinkSetStatMessageParser(array, startPosition, context.getChooser());
    }

    public static final SftpRequestLinkSetStatMessagePreparator PREPARATOR =
            new SftpRequestLinkSetStatMessagePreparator();

    public static final SftpRequestLinkSetStatMessageSerializer SERIALIZER =
            new SftpRequestLinkSetStatMessageSerializer();
}
