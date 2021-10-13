/**
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * <p>Copyright 2014-2021 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * <p>Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.transport.handler;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.sshattacker.core.protocol.common.Handler;
import de.rub.nds.sshattacker.core.protocol.transport.message.UnknownMessage;
import de.rub.nds.sshattacker.core.state.SshContext;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class UnknownMessageHandler extends Handler<UnknownMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public UnknownMessageHandler(SshContext context) {
        super(context);
    }

    @Override
    public void adjustContext(UnknownMessage message) {
        LOGGER.debug(
                "Received unknown message:\n"
                        + ArrayConverter.bytesToHexString(message.getPayload()));
    }
}
