/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.handler.holder;

import de.rub.nds.sshattacker.core.data.sftp.message.holder.SftpFileAttributes;
import de.rub.nds.sshattacker.core.data.sftp.parser.holder.SftpFileAttributesParser;
import de.rub.nds.sshattacker.core.data.sftp.preperator.holder.SftpFileAttributesPreparator;
import de.rub.nds.sshattacker.core.data.sftp.serializer.holder.SftpFileAttributesSerializer;
import de.rub.nds.sshattacker.core.protocol.common.Handler;
import de.rub.nds.sshattacker.core.state.SshContext;

public class SftpFileAttributesHandler implements Handler<SftpFileAttributes> {

    private final SshContext context;

    private final SftpFileAttributes attributes;

    public SftpFileAttributesHandler(SshContext context) {
        this(context, null);
    }

    public SftpFileAttributesHandler(SshContext context, SftpFileAttributes attributes) {
        super();
        this.context = context;
        this.attributes = attributes;
    }

    @Override
    public void adjustContext() {}

    @Override
    public SftpFileAttributesParser getParser(byte[] array) {
        return new SftpFileAttributesParser(array, context.getChooser());
    }

    @Override
    public SftpFileAttributesParser getParser(byte[] array, int startPosition) {
        return new SftpFileAttributesParser(array, startPosition, context.getChooser());
    }

    public static final SftpFileAttributesPreparator PREPARATOR =
            new SftpFileAttributesPreparator();

    public static final SftpFileAttributesSerializer SERIALIZER =
            new SftpFileAttributesSerializer();
}
