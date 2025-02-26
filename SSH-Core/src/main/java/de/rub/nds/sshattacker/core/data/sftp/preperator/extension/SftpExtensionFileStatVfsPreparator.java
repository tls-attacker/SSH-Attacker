/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.preperator.extension;

import de.rub.nds.sshattacker.core.constants.SftpExtension;
import de.rub.nds.sshattacker.core.data.sftp.message.extension.SftpExtensionFileStatVfs;
import de.rub.nds.sshattacker.core.workflow.chooser.Chooser;

public class SftpExtensionFileStatVfsPreparator
        extends SftpExtensionWithVersionPreparator<SftpExtensionFileStatVfs> {

    public SftpExtensionFileStatVfsPreparator() {
        super(SftpExtension.F_STAT_VFS_OPENSSH_COM);
    }

    @Override
    public void prepareExtensionSpecificContents(SftpExtensionFileStatVfs object, Chooser chooser) {
        object.setVersion("2", true);
    }
}
