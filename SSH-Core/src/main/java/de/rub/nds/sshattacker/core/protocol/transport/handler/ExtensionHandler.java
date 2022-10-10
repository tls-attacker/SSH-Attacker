/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.transport.handler;

import de.rub.nds.sshattacker.core.protocol.transport.message.Extension;
import de.rub.nds.sshattacker.core.protocol.transport.parser.ExtensionParser;

public abstract class ExtensionHandler {

    protected Extension extension;

    public ExtensionHandler(Extension ext) {
        this.extension = ext;
    }

    public abstract ExtensionParser getParser(byte[] array);
}
