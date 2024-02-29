/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.ssh1.handler;

import de.rub.nds.sshattacker.core.layer.context.SshContext;
import de.rub.nds.sshattacker.core.protocol.common.SshMessageHandler;
import de.rub.nds.sshattacker.core.protocol.ssh1.message.X11RequestForwardMessageSSH1;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class X11RequestForwardMessageSSHV1Handler
        extends SshMessageHandler<X11RequestForwardMessageSSH1> {

    private static final Logger LOGGER = LogManager.getLogger();

    public X11RequestForwardMessageSSHV1Handler(SshContext context) {
        super(context);
    }

    @Override
    public void adjustContext(X11RequestForwardMessageSSH1 message) {
        LOGGER.warn(
                "Forwarding X11 Request with Authentication Protocol {}, Authentication Data {} and screen Number {} ",
                message.getX11AuthenticationProtocol().getValue(),
                message.getX11AuthenticationData().getValue(),
                message.getScreenNumber().getValue());
    }
}
