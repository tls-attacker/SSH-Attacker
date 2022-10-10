/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.transport.handler;

import de.rub.nds.sshattacker.core.protocol.transport.message.Extension;
import de.rub.nds.sshattacker.core.protocol.transport.parser.ServerSigAlgsExtensionParser;

public class ServerSigAlgsExtensionHandler extends ExtensionHandler {

    public ServerSigAlgsExtensionHandler(Extension ext) {
        super(ext);
    }

    @Override
    public ServerSigAlgsExtensionParser getParser(byte[] array) {
        return new ServerSigAlgsExtensionParser(array);
    }
}
