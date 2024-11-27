/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.preperator.holder;

import de.rub.nds.sshattacker.core.data.sftp.message.holder.SftpFileAttributes;
import de.rub.nds.sshattacker.core.data.sftp.message.holder.SftpFileNameEntry;
import de.rub.nds.sshattacker.core.protocol.common.Preparator;
import de.rub.nds.sshattacker.core.workflow.chooser.Chooser;

public class SftpFileNameEntryPreparator extends Preparator<SftpFileNameEntry> {

    public SftpFileNameEntryPreparator(Chooser chooser, SftpFileNameEntry nameEntry) {
        super(chooser, nameEntry);
    }

    @Override
    public final void prepare() {
        if (getObject().getFilename() == null
                || getObject().getFilename().getOriginalValue() == null) {
            getObject().setFilename("/etc/passwd", true);
        }
        if (getObject().getFilenameLength() == null
                || getObject().getFilenameLength().getOriginalValue() == null) {
            getObject().setFilenameLength(getObject().getFilename().getValue().length());
        }

        if (chooser.getSftpNegotiatedVersion() <= 3
                || !chooser.getConfig().getRespectSftpNegotiatedVersion()) {
            if (getObject().getLongName() == null
                    || getObject().getLongName().getOriginalValue() == null) {
                getObject()
                        .setLongName(
                                "-rwxr-xr-x   1 ssh      attacker   348911 Mar 25 14:29 passwd",
                                true);
            }
            if (getObject().getLongNameLength() == null
                    || getObject().getLongNameLength().getOriginalValue() == null) {
                getObject().setLongNameLength(getObject().getLongName().getValue().length());
            }
        } else {
            // As of version 4 there is no longer a longName field
            getObject().clearLongName();
        }

        if (getObject().getAttributes() == null) {
            getObject().setAttributes(new SftpFileAttributes());
        }
        getObject().getAttributes().getHandler(chooser.getContext()).getPreparator().prepare();
    }
}
