/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.handler.attribute;

import de.rub.nds.sshattacker.core.data.sftp.message.attribute.SftpFileAttributes;
import de.rub.nds.sshattacker.core.data.sftp.parser.attribute.SftpFileAttributesParser;
import de.rub.nds.sshattacker.core.data.sftp.preperator.attribute.SftpFileAttributesPreparator;
import de.rub.nds.sshattacker.core.data.sftp.serializer.attribute.SftpFileAttributesSerializer;
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
        return new SftpFileAttributesParser(array);
    }

    @Override
    public SftpFileAttributesParser getParser(byte[] array, int startPosition) {
        return new SftpFileAttributesParser(array, startPosition);
    }

    @Override
    public SftpFileAttributesPreparator getPreparator() {
        return new SftpFileAttributesPreparator(context.getChooser(), attributes);
    }

    @Override
    public SftpFileAttributesSerializer getSerializer() {
        return new SftpFileAttributesSerializer(attributes);
    }
}
