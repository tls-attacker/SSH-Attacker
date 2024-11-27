/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.preperator.extension;

import de.rub.nds.sshattacker.core.data.sftp.message.extension.SftpExtensionUnknown;
import de.rub.nds.sshattacker.core.workflow.chooser.Chooser;

public class SftpExtensionUnknownPreparator
        extends SftpAbstractExtensionPreparator<SftpExtensionUnknown> {

    public SftpExtensionUnknownPreparator(Chooser chooser, SftpExtensionUnknown extension) {
        super(chooser, extension);
    }

    @Override
    public void prepareExtensionSpecificContents() {
        if (getObject().getName() == null || getObject().getName().getOriginalValue() == null) {
            getObject().setName("hello-from@ssh-attacker.de", true);
        }
        if (getObject().getNameLength() == null || getObject().getNameLength().getOriginalValue() == null) {
            getObject().setNameLength(getObject().getName().getValue().length());
        }

        if (getObject().getValue() == null || getObject().getValue().getOriginalValue() == null) {
            getObject().setValue(new byte[100], true);
        }
        if (getObject().getValueLength() == null || getObject().getValueLength().getOriginalValue() == null) {
            getObject().setValueLength(getObject().getValue().getValue().length);
        }
    }
}
