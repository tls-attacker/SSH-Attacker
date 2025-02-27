/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.common.handler.extended_request;

import de.rub.nds.sshattacker.core.data.sftp.common.handler.request.SftpRequestMessageHandler;
import de.rub.nds.sshattacker.core.data.sftp.common.message.extended_request.SftpRequestLinkSetStatMessage;
import de.rub.nds.sshattacker.core.data.sftp.common.parser.extended_request.SftpRequestLinkSetStatMessageParser;
import de.rub.nds.sshattacker.core.data.sftp.common.preperator.extended_request.SftpRequestLinkSetStatMessagePreparator;
import de.rub.nds.sshattacker.core.data.sftp.common.serializer.extended_request.SftpRequestLinkSetStatMessageSerializer;
import de.rub.nds.sshattacker.core.state.SshContext;

public class SftpRequestLinkSetStatMessageHandler
        extends SftpRequestMessageHandler<SftpRequestLinkSetStatMessage> {

    @Override
    public SftpRequestLinkSetStatMessageParser getParser(byte[] array, SshContext context) {
        return new SftpRequestLinkSetStatMessageParser(array);
    }

    @Override
    public SftpRequestLinkSetStatMessageParser getParser(
            byte[] array, int startPosition, SshContext context) {
        return new SftpRequestLinkSetStatMessageParser(array, startPosition);
    }

    public static final SftpRequestLinkSetStatMessagePreparator PREPARATOR =
            new SftpRequestLinkSetStatMessagePreparator();

    public static final SftpRequestLinkSetStatMessageSerializer SERIALIZER =
            new SftpRequestLinkSetStatMessageSerializer();
}
