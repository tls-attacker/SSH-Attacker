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
