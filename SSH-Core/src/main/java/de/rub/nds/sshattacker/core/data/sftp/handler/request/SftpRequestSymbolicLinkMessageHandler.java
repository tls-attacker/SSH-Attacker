/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.handler.request;

import de.rub.nds.sshattacker.core.data.sftp.message.request.SftpRequestSymbolicLinkMessage;
import de.rub.nds.sshattacker.core.data.sftp.parser.request.SftpRequestSymbolicLinkMessageParser;
import de.rub.nds.sshattacker.core.data.sftp.preperator.request.SftpRequestSymbolicLinkMessagePreparator;
import de.rub.nds.sshattacker.core.data.sftp.serializer.request.SftpRequestSymbolicLinkMessageSerializer;
import de.rub.nds.sshattacker.core.state.SshContext;

public class SftpRequestSymbolicLinkMessageHandler
        extends SftpRequestMessageHandler<SftpRequestSymbolicLinkMessage> {

    @Override
    public SftpRequestSymbolicLinkMessageParser getParser(byte[] array, SshContext context) {
        return new SftpRequestSymbolicLinkMessageParser(array);
    }

    @Override
    public SftpRequestSymbolicLinkMessageParser getParser(
            byte[] array, int startPosition, SshContext context) {
        return new SftpRequestSymbolicLinkMessageParser(array, startPosition);
    }

    public static final SftpRequestSymbolicLinkMessagePreparator PREPARATOR =
            new SftpRequestSymbolicLinkMessagePreparator();

    public static final SftpRequestSymbolicLinkMessageSerializer SERIALIZER =
            new SftpRequestSymbolicLinkMessageSerializer();
}
