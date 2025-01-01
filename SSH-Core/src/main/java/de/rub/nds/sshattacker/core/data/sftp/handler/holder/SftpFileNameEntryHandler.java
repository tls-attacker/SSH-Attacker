/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.handler.holder;

import de.rub.nds.sshattacker.core.data.sftp.message.holder.SftpFileNameEntry;
import de.rub.nds.sshattacker.core.data.sftp.parser.holder.SftpFileNameEntryParser;
import de.rub.nds.sshattacker.core.data.sftp.preperator.holder.SftpFileNameEntryPreparator;
import de.rub.nds.sshattacker.core.data.sftp.serializer.holder.SftpFileNameEntrySerializer;
import de.rub.nds.sshattacker.core.protocol.common.Handler;
import de.rub.nds.sshattacker.core.state.SshContext;

public class SftpFileNameEntryHandler implements Handler<SftpFileNameEntry> {

    @Override
    public void adjustContext(SshContext context, SftpFileNameEntry object) {}

    @Override
    public SftpFileNameEntryParser getParser(byte[] array, SshContext context) {
        return new SftpFileNameEntryParser(array, context.getChooser());
    }

    @Override
    public SftpFileNameEntryParser getParser(byte[] array, int startPosition, SshContext context) {
        return new SftpFileNameEntryParser(array, startPosition, context.getChooser());
    }

    public static final SftpFileNameEntryPreparator PREPARATOR = new SftpFileNameEntryPreparator();

    public static final SftpFileNameEntrySerializer SERIALIZER = new SftpFileNameEntrySerializer();
}
