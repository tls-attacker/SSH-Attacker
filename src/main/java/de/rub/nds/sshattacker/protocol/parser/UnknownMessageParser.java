package de.rub.nds.sshattacker.protocol.parser;

import de.rub.nds.sshattacker.protocol.message.UnknownMessage;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class UnknownMessageParser extends MessageParser<UnknownMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public UnknownMessageParser(int startposition, byte[] array) {
        super(startposition, array);
    }

    @Override
    public UnknownMessage createMessage() {
        return new UnknownMessage();
    }

    @Override
    protected void parseMessageSpecificPayload(UnknownMessage msg) {
        msg.setPayload(parseArrayOrTillEnd(-1));
        LOGGER.debug("Payload: " + msg.getPayload().getValue());
    }
}
