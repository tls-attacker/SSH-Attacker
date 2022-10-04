package de.rub.nds.sshattacker.core.protocol.transport.handler;

import de.rub.nds.modifiablevariable.string.ModifiableString;
import de.rub.nds.sshattacker.core.protocol.transport.message.Extension;
import de.rub.nds.sshattacker.core.protocol.transport.parser.ExtensionParser;
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
