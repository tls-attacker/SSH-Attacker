/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.transport.handler.extension;

import de.rub.nds.sshattacker.core.layer.context.SshContext;
import de.rub.nds.sshattacker.core.protocol.common.Handler;
import de.rub.nds.sshattacker.core.protocol.transport.message.extension.AbstractExtension;

public abstract class AbstractExtensionHandler<E extends AbstractExtension<E>>
        implements Handler<E> {

    protected final SshContext context;

    protected final E extension;

    protected AbstractExtensionHandler(SshContext context) {
        this(context, null);
    }

    protected AbstractExtensionHandler(SshContext context, E extension) {
        super();
        this.context = context;
        this.extension = extension;
    }
}
