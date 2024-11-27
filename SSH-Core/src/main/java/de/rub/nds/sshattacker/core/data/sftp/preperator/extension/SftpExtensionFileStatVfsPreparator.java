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

    public SftpExtensionFileStatVfsPreparator(
            Chooser chooser, SftpExtensionFileStatVfs extension, SftpExtension extensionName) {
        super(chooser, extension, extensionName);
    }

    @Override
    public void prepareExtensionSpecificContents() {
        if (getObject().getVersion() == null || getObject().getVersion().getOriginalValue() == null) {
            getObject().setVersion("2", true);
        }
        super.prepareExtensionSpecificContents();
    }
}
