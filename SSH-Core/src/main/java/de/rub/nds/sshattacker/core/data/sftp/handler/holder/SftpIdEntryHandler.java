/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.handler.holder;

import de.rub.nds.sshattacker.core.data.sftp.message.holder.SftpIdEntry;
import de.rub.nds.sshattacker.core.data.sftp.parser.holder.SftpIdEntryParser;
import de.rub.nds.sshattacker.core.data.sftp.preperator.holder.SftpIdEntryPreparator;
import de.rub.nds.sshattacker.core.data.sftp.serializer.holder.SftpIdEntrySerializer;
import de.rub.nds.sshattacker.core.protocol.common.Handler;
import de.rub.nds.sshattacker.core.state.SshContext;

public class SftpIdEntryHandler implements Handler<SftpIdEntry> {

    private final SshContext context;

    private final SftpIdEntry idEntry;

    public SftpIdEntryHandler(SshContext context) {
        this(context, null);
    }

    public SftpIdEntryHandler(SshContext context, SftpIdEntry idEntry) {
        super();
        this.context = context;
        this.idEntry = idEntry;
    }

    @Override
    public void adjustContext() {}

    @Override
    public SftpIdEntryParser getParser(byte[] array) {
        return new SftpIdEntryParser(array);
    }

    @Override
    public SftpIdEntryParser getParser(byte[] array, int startPosition) {
        return new SftpIdEntryParser(array, startPosition);
    }

    public static final SftpIdEntryPreparator PREPARATOR = new SftpIdEntryPreparator();

    @Override
    public SftpIdEntrySerializer getSerializer() {
        return new SftpIdEntrySerializer(idEntry);
    }
}
