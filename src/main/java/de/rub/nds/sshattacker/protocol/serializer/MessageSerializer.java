package de.rub.nds.sshattacker.protocol.serializer;

import de.rub.nds.protocol.core.message.Serializer;
import de.rub.nds.sshattacker.constants.MessageIDConstants;
import de.rub.nds.sshattacker.protocol.message.ECDHKeyExchangeInitMessage;
import de.rub.nds.sshattacker.protocol.message.ECDHKeyExchangeReplyMessage;
import de.rub.nds.sshattacker.protocol.message.KeyExchangeInitMessage;
import de.rub.nds.sshattacker.protocol.message.Message;
import de.rub.nds.sshattacker.protocol.message.NewKeysMessage;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public abstract class MessageSerializer<T extends Message> extends Serializer<Message> {

    private static final Logger LOGGER = LogManager.getLogger();

    private final T msg;

    public MessageSerializer(T msg) {
        this.msg = msg;
    }

    @Override
    protected byte[] serializeBytes() {
        appendByte(msg.getMessageID().getValue());
        serializeMessageSpecificPayload();
        return getAlreadySerialized();
    }

    protected abstract byte[] serializeMessageSpecificPayload();

    public static <T extends Message> byte[] delegateSerialization(T message) {
        switch (message.getMessageID().getValue()) {
            case MessageIDConstants.SSH_MSG_KEXINIT:
                return new KeyExchangeInitMessageSerializer((KeyExchangeInitMessage) message).serialize();
            case MessageIDConstants.SSH_MSG_KEX_ECDH_INIT:
                return new ECDHKeyExchangeInitMessageSerializer((ECDHKeyExchangeInitMessage) message).serialize();
            case MessageIDConstants.SSH_MSG_KEX_ECDH_REPLY:
                return new ECDHKeyExchangeReplyMessageSerializer((ECDHKeyExchangeReplyMessage) message).serialize();
            case MessageIDConstants.SSH_MSG_NEWKEYS:
                return new NewKeysMessageSerializer((NewKeysMessage) message).serialize();
            default:
                LOGGER.debug("Tried to serialize a Message with unknown MessageID " + message.getMessageID().getValue());
                return new byte[0];
        }
    }
;

}
