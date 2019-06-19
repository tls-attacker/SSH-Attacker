package de.rub.nds.sshattacker.protocol.handler;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.sshattacker.protocol.message.UnknownMessage;
import de.rub.nds.sshattacker.state.SshContext;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class UnknownMessageHandler extends Handler<UnknownMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public UnknownMessageHandler(SshContext context) {
        super(context);
    }

    @Override
    public void handle(UnknownMessage msg) {
        LOGGER.debug("Received UnknownMessage:\n" + ArrayConverter.bytesToHexString(msg.getPayload()));
    }

}
