/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.handler.holder;

import de.rub.nds.sshattacker.core.data.sftp.message.holder.SftpNameEntry;
import de.rub.nds.sshattacker.core.data.sftp.parser.holder.SftpNameEntryParser;
import de.rub.nds.sshattacker.core.data.sftp.preperator.holder.SftpNameEntryPreparator;
import de.rub.nds.sshattacker.core.data.sftp.serializer.holder.SftpNameEntrySerializer;
import de.rub.nds.sshattacker.core.protocol.common.Handler;
import de.rub.nds.sshattacker.core.state.SshContext;

public class SftpNameEntryHandler implements Handler<SftpNameEntry> {

    private final SshContext context;

    private final SftpNameEntry nameEntry;

    public SftpNameEntryHandler(SshContext context) {
        this(context, null);
    }

    public SftpNameEntryHandler(SshContext context, SftpNameEntry nameEntry) {
        super();
        this.context = context;
        this.nameEntry = nameEntry;
    }

    @Override
    public void adjustContext() {}

    @Override
    public SftpNameEntryParser getParser(byte[] array) {
        return new SftpNameEntryParser(array);
    }

    @Override
    public SftpNameEntryParser getParser(byte[] array, int startPosition) {
        return new SftpNameEntryParser(array, startPosition);
    }

    @Override
    public SftpNameEntryPreparator getPreparator() {
        return new SftpNameEntryPreparator(context.getChooser(), nameEntry);
    }

    @Override
    public SftpNameEntrySerializer getSerializer() {
        return new SftpNameEntrySerializer(nameEntry);
    }
}
