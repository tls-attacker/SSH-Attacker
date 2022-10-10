/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.transport.parser;

import de.rub.nds.sshattacker.core.protocol.common.Parser;
import de.rub.nds.sshattacker.core.protocol.transport.message.Extension;

public abstract class ExtensionParser extends Parser<Extension> {

    public ExtensionParser(byte[] extension) {
        super(extension);
    }

    protected abstract byte[] parseExtensionName();

    protected abstract byte[] parseExtensionValue();

    @Override
    public abstract Extension parse();
}
