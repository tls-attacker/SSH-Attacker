/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.common.handler;

import de.rub.nds.sshattacker.core.data.sftp.SftpMessageHandler;
import de.rub.nds.sshattacker.core.data.sftp.common.message.SftpInitMessage;
import de.rub.nds.sshattacker.core.data.sftp.common.parser.SftpInitMessageParser;
import de.rub.nds.sshattacker.core.data.sftp.common.preparator.SftpInitMessagePreparator;
import de.rub.nds.sshattacker.core.data.sftp.common.serializer.SftpInitMessageSerializer;
import de.rub.nds.sshattacker.core.protocol.common.MessageSentHandler;
import de.rub.nds.sshattacker.core.state.SshContext;

public class SftpInitMessageHandler extends SftpMessageHandler<SftpInitMessage>
        implements MessageSentHandler<SftpInitMessage> {

    @Override
    public void adjustContext(SshContext context, SftpInitMessage object) {
        context.setSftpClientVersion(object.getVersion().getValue());
        context.setSftpClientSupportedExtensions(object.getExtensions());
        object.getExtensions().forEach(extension -> extension.adjustContext(context));
    }

    @Override
    public void adjustContextAfterMessageSent(SshContext context, SftpInitMessage object) {
        if (context.isClient()) {
            context.setSftpClientVersion(object.getVersion().getValue());
            context.setSftpClientSupportedExtensions(object.getExtensions());
        }
    }

    @Override
    public SftpInitMessageParser getParser(byte[] array, SshContext context) {
        return new SftpInitMessageParser(array);
    }

    @Override
    public SftpInitMessageParser getParser(byte[] array, int startPosition, SshContext context) {
        return new SftpInitMessageParser(array, startPosition);
    }

    public static final SftpInitMessagePreparator PREPARATOR = new SftpInitMessagePreparator();

    public static final SftpInitMessageSerializer SERIALIZER = new SftpInitMessageSerializer();
}
