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
