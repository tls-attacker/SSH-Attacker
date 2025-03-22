/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.common.preparator.extension;

import de.rub.nds.sshattacker.core.constants.SftpExtension;
import de.rub.nds.sshattacker.core.data.sftp.common.message.extension.SftpExtensionWithVersion;
import de.rub.nds.sshattacker.core.workflow.chooser.Chooser;

public class SftpExtensionWithVersionPreparator<T extends SftpExtensionWithVersion<T>>
        extends SftpAbstractExtensionPreparator<T> {

    public SftpExtensionWithVersionPreparator(SftpExtension extensionName) {
        super(extensionName);
    }

    @Override
    protected void prepareExtensionSpecificContents(T object, Chooser chooser) {
        object.setVersion("1", true);
    }
}
