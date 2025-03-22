/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.transport.preparator.extension;

import de.rub.nds.sshattacker.core.constants.Extension;
import de.rub.nds.sshattacker.core.protocol.common.Preparator;
import de.rub.nds.sshattacker.core.protocol.transport.message.extension.AbstractExtension;
import de.rub.nds.sshattacker.core.workflow.chooser.Chooser;

public abstract class AbstractExtensionPreparator<T extends AbstractExtension<T>>
        extends Preparator<T> {

    private final String extensionName;

    protected AbstractExtensionPreparator(Extension extensionName) {
        this(extensionName.getName());
    }

    protected AbstractExtensionPreparator(String extensionName) {
        super();
        this.extensionName = extensionName;
    }

    @Override
    public void prepare(T object, Chooser chooser) {
        object.setName(extensionName, true);
        prepareExtensionSpecificContents(object, chooser);
    }

    protected abstract void prepareExtensionSpecificContents(T object, Chooser chooser);
}
