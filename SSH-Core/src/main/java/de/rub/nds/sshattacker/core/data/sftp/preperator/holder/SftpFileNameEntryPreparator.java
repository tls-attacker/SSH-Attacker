/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.preperator.holder;

import de.rub.nds.sshattacker.core.data.sftp.message.holder.SftpFileNameEntry;
import de.rub.nds.sshattacker.core.protocol.common.Preparator;
import de.rub.nds.sshattacker.core.workflow.chooser.Chooser;

public class SftpFileNameEntryPreparator extends Preparator<SftpFileNameEntry> {

    public SftpFileNameEntryPreparator(Chooser chooser, SftpFileNameEntry nameEntry) {
        super(chooser, nameEntry);
    }

    @Override
    public final void prepare() {
        getObject().setSoftlyFilename("/etc/passwd", true, chooser.getConfig());

        if (chooser.getSftpNegotiatedVersion() <= 3
                || !chooser.getConfig().getRespectSftpNegotiatedVersion()) {
            getObject()
                    .setSoftlyLongName(
                            "-rwxr-xr-x   1 ssh      attacker   348911 Mar 25 14:29 passwd",
                            true,
                            chooser.getConfig());
        } else {
            // As of version 4 there is no longer a longName field
            getObject().clearLongName();
        }

        getObject().getAttributes().getHandler(chooser.getContext()).getPreparator().prepare();
    }
}
