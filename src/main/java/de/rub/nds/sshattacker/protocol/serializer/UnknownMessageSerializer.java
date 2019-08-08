package de.rub.nds.sshattacker.protocol.serializer;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.sshattacker.protocol.message.UnknownMessage;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class UnknownMessageSerializer extends MessageSerializer<UnknownMessage> {

    private final UnknownMessage msg;
    private static final Logger LOGGER = LogManager.getLogger();

    public UnknownMessageSerializer(UnknownMessage msg) {
        super(msg);
        this.msg = msg;
    }

    @Override
    protected byte[] serializeMessageSpecificPayload() {
        LOGGER.debug("Payload: " + ArrayConverter.bytesToHexString(msg.getPayload()));
        appendBytes(msg.getPayload().getValue());
        return getAlreadySerialized();
    }
}
