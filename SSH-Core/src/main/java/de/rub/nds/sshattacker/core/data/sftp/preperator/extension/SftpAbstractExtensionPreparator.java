/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.preperator.extension;

import de.rub.nds.sshattacker.core.constants.SftpExtension;
import de.rub.nds.sshattacker.core.data.sftp.message.extension.SftpAbstractExtension;
import de.rub.nds.sshattacker.core.protocol.common.Preparator;
import de.rub.nds.sshattacker.core.workflow.chooser.Chooser;

public abstract class SftpAbstractExtensionPreparator<E extends SftpAbstractExtension<E>>
        extends Preparator<E> {

    private final String extensionName;

    protected SftpAbstractExtensionPreparator(
            Chooser chooser, E extension, SftpExtension extensionName) {
        this(chooser, extension, extensionName.getName());
    }

    protected SftpAbstractExtensionPreparator(Chooser chooser, E extension, String extensionName) {
        super(chooser, extension);
        this.extensionName = extensionName;
    }

    @Override
    public void prepare() {
        if (extensionName != null) {
            getObject().setSoftlyName(extensionName, true, chooser.getConfig());
        }
        prepareExtensionSpecificContents();
    }

    protected abstract void prepareExtensionSpecificContents();
}
