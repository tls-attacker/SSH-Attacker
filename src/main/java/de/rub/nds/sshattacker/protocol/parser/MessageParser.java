package de.rub.nds.sshattacker.protocol.parser;

import de.rub.nds.protocol.core.message.Parser;
import de.rub.nds.sshattacker.constants.MessageIDConstant;
import de.rub.nds.sshattacker.protocol.message.Message;
import org.apache.logging.log4j.LogManager;

public abstract class MessageParser<T extends Message> extends Parser<T> {

    private static final org.apache.logging.log4j.Logger LOGGER = LogManager.getLogger();

    public MessageParser(int startposition, byte[] array) {
        super(startposition, array);
    }

    public abstract T createMessage();

    protected abstract void parseMessageSpecificPayload(T msg);

    private void parseMessageID(T msg) {
        msg.setMessageID(parseByteField(1));
    }

    @Override
    public T parse() {
        T msg = createMessage();
        parseMessageID(msg);
        parseMessageSpecificPayload(msg);
        return msg;
    }

    public static Message delegateParsing(byte[] raw) {
        switch (MessageIDConstant.fromId(raw[0])) {
            case SSH_MSG_KEXINIT:
                return new KeyExchangeInitMessageParser(0, raw).parse();
            case SSH_MSG_KEX_ECDH_INIT:
                return new EcdhKeyExchangeInitMessageParser(0, raw).parse();
            case SSH_MSG_KEX_ECDH_REPLY:
                return new EcdhKeyExchangeReplyMessageParser(0, raw).parse();
            case SSH_MSG_NEWKEYS:
                return new NewKeysMessageParser(0, raw).parse();
            case SSH_MSG_SERVICE_REQUEST:
                return new ServiceRequestMessageParser(0, raw).parse();
            case SSH_MSG_SERVICE_ACCEPT:
                return new ServiceAcceptMessageParser(0, raw).parse();
            case SSH_MSG_CHANNEL_OPEN_CONFIRMATION:
                return new ChannelOpenConfirmationMessageParser(0, raw).parse();
            case SSH_MSG_CHANNEL_DATA:
                return new ChannelDataMessageParser(0, raw).parse();
            default:
                LOGGER.debug("Received unimplemented Message " + MessageIDConstant.getNameByID(raw[0]) + " (" + raw[0] + ")");
                return new UnknownMessageParser(0, raw).parse();
        }
    }
}
