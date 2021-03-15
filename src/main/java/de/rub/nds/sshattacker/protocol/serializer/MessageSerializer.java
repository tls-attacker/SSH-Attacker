package de.rub.nds.sshattacker.protocol.serializer;

import de.rub.nds.protocol.core.message.Serializer;
import de.rub.nds.sshattacker.constants.DataFormatConstants;
import de.rub.nds.sshattacker.protocol.message.Message;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public abstract class MessageSerializer<T extends Message> extends Serializer<Message> {

    private static final Logger LOGGER = LogManager.getLogger();

    protected final T msg;

    public MessageSerializer(T msg) {
        this.msg = msg;
    }

    @Override
    protected byte[] serializeBytes() {
        appendByte(msg.getMessageID().getValue());
        serializeMessageSpecificPayload();
        return getAlreadySerialized();
    }

    protected final void serializeSshString(String string) {
        appendInt(string.length(), DataFormatConstants.STRING_SIZE_LENGTH);
        appendString(string);
    }

    protected abstract byte[] serializeMessageSpecificPayload();

    public static <T extends Message> byte[] delegateSerialization(T message) {
        return message.getSerializer().serialize();
    }
}
