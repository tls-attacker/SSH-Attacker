/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.transport.handler.extension;

import de.rub.nds.sshattacker.core.layer.context.SshContext;
import de.rub.nds.sshattacker.core.protocol.transport.message.extension.AbstractExtension;
import de.rub.nds.sshattacker.core.protocol.transport.message.extension.UnknownExtension;

public class UnknownExtensionHandler extends AbstractExtensionHandler<UnknownExtension> {

    public UnknownExtensionHandler(SshContext context) {
        super(context);
    }

    public UnknownExtensionHandler(SshContext context, UnknownExtension extension) {
        super(context, extension);
    }

    @Override
    public void adjustContext(AbstractExtension<?> extension) {
        adjustContext((UnknownExtension) extension);
    }

    @Override
    public void adjustContext(UnknownExtension extension) {
        // TODO: Handle UnknownExtension
    }
}
