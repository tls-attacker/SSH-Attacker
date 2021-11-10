/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2021 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.common;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.sshattacker.core.constants.MessageIDConstant;
import de.rub.nds.sshattacker.core.exceptions.ParserException;
import de.rub.nds.sshattacker.core.protocol.authentication.parser.UserAuthBannerMessageParser;
import de.rub.nds.sshattacker.core.protocol.authentication.parser.UserAuthFailureMessageParser;
import de.rub.nds.sshattacker.core.protocol.authentication.parser.UserAuthSuccessMessageParser;
import de.rub.nds.sshattacker.core.protocol.connection.parser.*;
import de.rub.nds.sshattacker.core.protocol.packet.AbstractPacket;
import de.rub.nds.sshattacker.core.protocol.packet.BlobPacket;
import de.rub.nds.sshattacker.core.protocol.transport.parser.*;
import de.rub.nds.sshattacker.core.state.SshContext;
import java.nio.charset.StandardCharsets;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public abstract class ProtocolMessageParser<T extends ProtocolMessage<T>> extends Parser<T> {

    private static final Logger LOGGER = LogManager.getLogger();

    protected final T message = createMessage();

    public ProtocolMessageParser(byte[] array, int startPosition) {
        super(array, startPosition);
    }

    @Override
    public final T parse() {
        parseProtocolMessageContents();
        setCompleteResultingMessage();
        return message;
    }

    protected abstract T createMessage();

    protected abstract void parseProtocolMessageContents();

    private void setCompleteResultingMessage() {
        message.setCompleteResultingMessage(getAlreadyParsed());
        LOGGER.debug(
                "CompleteResultMessage: "
                        + ArrayConverter.bytesToHexString(
                                message.getCompleteResultingMessage().getValue()));
    }

    public static ProtocolMessage<?> delegateParsing(AbstractPacket packet, SshContext context) {
        byte[] raw = packet.getPayload().getValue();
        try {
            if (packet instanceof BlobPacket) {
                String rawText =
                        new String(packet.getPayload().getValue(), StandardCharsets.US_ASCII);
                if (rawText.startsWith("SSH-2.0")) {
                    return new VersionExchangeMessageParser(raw, 0).parse();
                } else if (rawText.startsWith("Invalid SSH identification string.")) {
                    LOGGER.warn(
                            "The server reported the identification string sent by the SSH-Attacker is invalid");
                    // TODO: Implement InvalidIdentificationMessage
                    return null;
                }
            }

            switch (MessageIDConstant.fromId(raw[0], context)) {
                case SSH_MSG_KEXINIT:
                    return new KeyExchangeInitMessageParser(raw, 0).parse();
                case SSH_MSG_KEX_ECDH_INIT:
                    return new EcdhKeyExchangeInitMessageParser(raw, 0).parse();
                case SSH_MSG_KEX_ECDH_REPLY:
                    return new EcdhKeyExchangeReplyMessageParser(raw, 0).parse();
                case SSH_MSG_KEXDH_REPLY:
                    return new DhKeyExchangeReplyMessageParser(raw, 0).parse();
                case SSH_MSG_KEX_DH_GEX_GROUP:
                    return new DhGexKeyExchangeGroupMessageParser(raw, 0).parse();
                case SSH_MSG_KEX_DH_GEX_REPLY:
                    return new DhGexKeyExchangeReplyMessageParser(raw, 0).parse();
                case SSH_MSG_KEXRSA_PUBKEY:
                    return new RsaKeyExchangePubkeyMessageParser(raw, 0).parse();
                case SSH_MSG_NEWKEYS:
                    return new NewKeysMessageParser(raw, 0).parse();
                case SSH_MSG_SERVICE_REQUEST:
                    return new ServiceRequestMessageParser(raw, 0).parse();
                case SSH_MSG_SERVICE_ACCEPT:
                    return new ServiceAcceptMessageParser(raw, 0).parse();
                case SSH_MSG_CHANNEL_OPEN_CONFIRMATION:
                    return new ChannelOpenConfirmationMessageParser(raw, 0).parse();
                case SSH_MSG_CHANNEL_DATA:
                    return new ChannelDataMessageParser(raw, 0).parse();
                case SSH_MSG_CHANNEL_CLOSE:
                    return new ChannelCloseMessageParser(raw, 0).parse();
                case SSH_MSG_CHANNEL_EOF:
                    return new ChannelEofMessageParser(raw, 0).parse();
                case SSH_MSG_CHANNEL_EXTENDED_DATA:
                    return new ChannelExtendedDataMessageParser(raw, 0).parse();
                case SSH_MSG_CHANNEL_FAILURE:
                    return new ChannelFailureMessageParser(raw, 0).parse();
                case SSH_MSG_CHANNEL_OPEN_FAILURE:
                    return new ChannelOpenFailureMessageParser(raw, 0).parse();
                case SSH_MSG_CHANNEL_OPEN:
                    return new ChannelOpenMessageParser(raw, 0).parse();
                    // TODO: Reimplement channel requests
                case SSH_MSG_CHANNEL_SUCCESS:
                    return new ChannelSuccessMessageParser(raw, 0).parse();
                case SSH_MSG_CHANNEL_WINDOW_ADJUST:
                    return new ChannelWindowAdjustMessageParser(raw, 0).parse();
                case SSH_MSG_DEBUG:
                    return new DebugMessageParser(raw, 0).parse();
                case SSH_MSG_DISCONNECT:
                    return new DisconnectMessageParser(raw, 0).parse();
                    // TODO: Reimplement global requests
                case SSH_MSG_IGNORE:
                    return new IgnoreMessageParser(raw, 0).parse();
                case SSH_MSG_REQUEST_FAILURE:
                    return new RequestFailureMessageParser(raw, 0).parse();
                case SSH_MSG_REQUEST_SUCCESS:
                    return new RequestSuccessMessageParser(raw, 0).parse();
                case SSH_MSG_UNIMPLEMENTED:
                    return new UnimplementedMessageParser(raw, 0).parse();
                case SSH_MSG_USERAUTH_BANNER:
                    return new UserAuthBannerMessageParser(raw, 0).parse();
                case SSH_MSG_USERAUTH_FAILURE:
                    return new UserAuthFailureMessageParser(raw, 0).parse();
                case SSH_MSG_USERAUTH_SUCCESS:
                    return new UserAuthSuccessMessageParser(raw, 0).parse();

                default:
                    LOGGER.debug(
                            "Received unimplemented Message "
                                    + MessageIDConstant.getNameByID(raw[0])
                                    + " ("
                                    + raw[0]
                                    + ")");
                    return new UnknownMessageParser(raw, 0).parse();
            }
        } catch (ParserException e) {
            LOGGER.debug("Error while Parsing, now parsing as UnknownMessage");
            return new UnknownMessageParser(raw, 0).parse();
        }
    }
}
