/**
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2021 Ruhr University Bochum, Paderborn University,
 * and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.protocol.parser;

import de.rub.nds.sshattacker.exceptions.ParserException;
import de.rub.nds.sshattacker.constants.MessageIDConstant;
import de.rub.nds.sshattacker.protocol.message.Message;
import org.apache.logging.log4j.LogManager;

public abstract class MessageParser<T extends Message<T>> extends Parser<T> {

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

    public static Message<?> delegateParsing(byte[] raw) {
        try {
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
                case SSH_MSG_CHANNEL_CLOSE:
                    return new ChannelCloseMessageParser(0, raw).parse();
                case SSH_MSG_CHANNEL_EOF:
                    return new ChannelEofMessageParser(0, raw).parse();
                case SSH_MSG_CHANNEL_EXTENDED_DATA:
                    return new ChannelExtendedDataMessageParser(0, raw).parse();
                case SSH_MSG_CHANNEL_FAILURE:
                    return new ChannelFailureMessageParser(0, raw).parse();
                case SSH_MSG_CHANNEL_OPEN_FAILURE:
                    return new ChannelOpenFailureMessageParser(0, raw).parse();
                case SSH_MSG_CHANNEL_OPEN:
                    return new ChannelOpenMessageParser(0, raw).parse();
                case SSH_MSG_CHANNEL_REQUEST:
                    return new ChannelRequestMessageParser(0, raw).parse();
                case SSH_MSG_CHANNEL_SUCCESS:
                    return new ChannelSuccessMessageParser(0, raw).parse();
                case SSH_MSG_CHANNEL_WINDOW_ADJUST:
                    return new ChannelWindowAdjustMessageParser(0, raw).parse();
                case SSH_MSG_DEBUG:
                    return new DebugMessageParser(0, raw).parse();
                case SSH_MSG_DISCONNECT:
                    return new DisconnectMessageParser(0, raw).parse();
                case SSH_MSG_GLOBAL_REQUEST:
                    return new GlobalRequestMessageParser(0, raw).parse();
                case SSH_MSG_IGNORE:
                    return new IgnoreMessageParser(0, raw).parse();
                case SSH_MSG_REQUEST_FAILURE:
                    return new RequestFailureMessageParser(0, raw).parse();
                case SSH_MSG_REQUEST_SUCCESS:
                    return new RequestSuccessMessageParser(0, raw).parse();
                case SSH_MSG_UNIMPLEMENTED:
                    return new UnimplementedMessageParser(0, raw).parse();
                case SSH_MSG_USERAUTH_BANNER:
                    return new UserAuthBannerMessageParser(0, raw).parse();
                case SSH_MSG_USERAUTH_FAILURE:
                    return new UserAuthFailureMessageParser(0, raw).parse();
                case SSH_MSG_USERAUTH_SUCCESS:
                    return new UserAuthSuccessMessageParser(0, raw).parse();

                default:
                    LOGGER.debug("Received unimplemented Message " + MessageIDConstant.getNameByID(raw[0]) + " ("
                            + raw[0] + ")");
                    return new UnknownMessageParser(0, raw).parse();
            }
        } catch (ParserException e) {
            LOGGER.debug("Error while Parsing, now parsing as UnknownMessage");
            return new UnknownMessageParser(0, raw).parse();
        }
    }
}
