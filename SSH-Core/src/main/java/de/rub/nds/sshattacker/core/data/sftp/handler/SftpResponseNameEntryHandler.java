/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.handler;

import de.rub.nds.sshattacker.core.data.sftp.message.SftpResponseNameEntry;
import de.rub.nds.sshattacker.core.data.sftp.parser.SftpResponseNameEntryParser;
import de.rub.nds.sshattacker.core.data.sftp.preperator.SftpResponseNameEntryPreparator;
import de.rub.nds.sshattacker.core.data.sftp.serializer.SftpResponseNameEntrySerializer;
import de.rub.nds.sshattacker.core.protocol.common.Handler;
import de.rub.nds.sshattacker.core.state.SshContext;

public class SftpResponseNameEntryHandler implements Handler<SftpResponseNameEntry> {

    private final SshContext context;

    private final SftpResponseNameEntry nameEntry;

    public SftpResponseNameEntryHandler(SshContext context) {
        this(context, null);
    }

    public SftpResponseNameEntryHandler(SshContext context, SftpResponseNameEntry nameEntry) {
        super();
        this.context = context;
        this.nameEntry = nameEntry;
    }

    @Override
    public void adjustContext() {}

    @Override
    public SftpResponseNameEntryParser getParser(byte[] array) {
        return new SftpResponseNameEntryParser(array);
    }

    @Override
    public SftpResponseNameEntryParser getParser(byte[] array, int startPosition) {
        return new SftpResponseNameEntryParser(array, startPosition);
    }

    @Override
    public SftpResponseNameEntryPreparator getPreparator() {
        return new SftpResponseNameEntryPreparator(context.getChooser(), nameEntry);
    }

    @Override
    public SftpResponseNameEntrySerializer getSerializer() {
        return new SftpResponseNameEntrySerializer(nameEntry);
    }
}
