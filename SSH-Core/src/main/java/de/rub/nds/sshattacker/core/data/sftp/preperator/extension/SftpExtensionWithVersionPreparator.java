/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.preperator.extension;

import de.rub.nds.sshattacker.core.constants.SftpExtension;
import de.rub.nds.sshattacker.core.data.sftp.message.extension.SftpExtensionWithVersion;
import de.rub.nds.sshattacker.core.workflow.chooser.Chooser;

public class SftpExtensionWithVersionPreparator<T extends SftpExtensionWithVersion<T>>
        extends SftpAbstractExtensionPreparator<T> {

    private final String extensionName;

    public SftpExtensionWithVersionPreparator(
            Chooser chooser, T extension, SftpExtension extensionName) {
        super(chooser, extension);
        this.extensionName = extensionName.getName();
    }

    @Override
    public void prepareExtensionSpecificContents() {
        getObject().setName(extensionName, true);

        if (getObject().getVersion() == null || getObject().getVersion().getOriginalValue() == null) {
            getObject().setVersion("1", true);
        }
        if (getObject().getVersionLength() == null || getObject().getVersionLength().getOriginalValue() == null) {
            getObject().setVersionLength(getObject().getVersion().getValue().length());
        }
    }
}
