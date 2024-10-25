/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.ssh1.client.serializer;

import de.rub.nds.sshattacker.core.constants.DataFormatConstants;
import de.rub.nds.sshattacker.core.protocol.common.Ssh1MessageSerializer;
import de.rub.nds.sshattacker.core.protocol.ssh1.client.message.X11RequestForwardMessageSSH1;
import java.nio.charset.StandardCharsets;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class X11RequestForwardMessageSSHV1Serializier
        extends Ssh1MessageSerializer<X11RequestForwardMessageSSH1> {

    private static final Logger LOGGER = LogManager.getLogger();

    public X11RequestForwardMessageSSHV1Serializier(X11RequestForwardMessageSSH1 message) {
        super(message);
    }

    private void serializeExitStatus() {
        LOGGER.debug(
                "Forwarding X11 Request with Authentication Protocol {}, Authentication Data {} and screen Number {} ",
                message.getX11AuthenticationProtocol().getValue(),
                message.getX11AuthenticationData().getValue(),
                message.getScreenNumber().getValue());
        appendInt(
                message.getX11AuthenticationProtocol().getValue().length(),
                DataFormatConstants.UINT32_SIZE);
        appendString(message.getX11AuthenticationProtocol().getValue(), StandardCharsets.UTF_8);
        appendInt(
                message.getX11AuthenticationData().getValue().length(),
                DataFormatConstants.UINT32_SIZE);
        appendString(message.getX11AuthenticationData().getValue(), StandardCharsets.UTF_8);
        appendInt(message.getScreenNumber().getValue(), DataFormatConstants.UINT32_SIZE);
    }

    @Override
    public void serializeMessageSpecificContents() {
        serializeExitStatus();
    }
}
