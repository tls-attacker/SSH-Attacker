/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.preperator.response;

import de.rub.nds.sshattacker.core.data.sftp.message.attribute.SftpFileAttributes;
import de.rub.nds.sshattacker.core.data.sftp.message.response.SftpResponseNameEntry;
import de.rub.nds.sshattacker.core.protocol.common.Preparator;
import de.rub.nds.sshattacker.core.workflow.chooser.Chooser;

public class SftpResponseNameEntryPreparator extends Preparator<SftpResponseNameEntry> {

    public SftpResponseNameEntryPreparator(Chooser chooser, SftpResponseNameEntry attribute) {
        super(chooser, attribute);
    }

    @Override
    public final void prepare() {
        if (getObject().getFilename() == null) {
            getObject().setFilename("/etc/passwd", true);
        }
        if (getObject().getFilenameLength() == null) {
            getObject().setFilenameLength(getObject().getFilename().getValue().length());
        }

        if (getObject().getLongName() == null) {
            getObject()
                    .setLongName(
                            "-rwxr-xr-x   1 ssh      attacker   348911 Mar 25 14:29 passwd", true);
        }
        if (getObject().getLongNameLength() == null) {
            getObject().setLongNameLength(getObject().getLongName().getValue().length());
        }

        if (getObject().getAttributes() == null) {
            getObject().setAttributes(new SftpFileAttributes());
        }
        getObject().getAttributes().getHandler(chooser.getContext()).getPreparator().prepare();
    }
}
