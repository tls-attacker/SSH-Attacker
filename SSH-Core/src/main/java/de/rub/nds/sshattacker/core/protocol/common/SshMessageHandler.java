/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.common;

import de.rub.nds.sshattacker.core.layer.context.SshContext;

public abstract class SshMessageHandler<T extends SshMessage<T>> extends ProtocolMessageHandler<T> {

    public SshMessageHandler(SshContext context) {
        super(context);
    }

    /*public SshMessageHandler(SshContext context, T message) {
        super(context, message);
    }
     */

}
