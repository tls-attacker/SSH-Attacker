/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.common;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.sshattacker.core.constants.MessageIdConstant;
import de.rub.nds.sshattacker.core.exceptions.ParserException;
import de.rub.nds.sshattacker.core.packet.AbstractPacket;
import de.rub.nds.sshattacker.core.packet.BlobPacket;
import de.rub.nds.sshattacker.core.protocol.authentication.message.*;
import de.rub.nds.sshattacker.core.protocol.authentication.parser.*;
import de.rub.nds.sshattacker.core.protocol.connection.message.ChannelRequestUnknownMessage;
import de.rub.nds.sshattacker.core.protocol.connection.message.GlobalRequestUnknownMessage;
import de.rub.nds.sshattacker.core.protocol.connection.parser.*;
import de.rub.nds.sshattacker.core.protocol.transport.message.AsciiMessage;
import de.rub.nds.sshattacker.core.protocol.transport.parser.*;
import de.rub.nds.sshattacker.core.state.SshContext;
import java.nio.charset.StandardCharsets;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public abstract class ProtocolMessageParser<T extends ProtocolMessage<T>> extends Parser<T> {

    private static final Logger LOGGER = LogManager.getLogger();

    protected final T message = createMessage();

    public ProtocolMessageParser(byte[] array) {
        super(array);
    }

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
        LOGGER.trace(
                "Complete message bytes parsed: "
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
                    return new VersionExchangeMessageParser(raw).parse();
                } else {
                    final AsciiMessage message = new AsciiMessageParser(raw).parse();

                    // If we know what the text message means we can print a
                    // human-readable warning to the log. The following
                    // messages are sent by OpenSSH.
                    final String messageText = message.getText().getValue();
                    if ("Invalid SSH identification string.".equals(messageText)) {
                        LOGGER.warn(
                                "The server reported the identification string sent by the SSH-Attacker is invalid");
                    } else if ("Exceeded MaxStartups".equals(messageText)) {
                        LOGGER.warn(
                                "The server reported the maximum number of concurrent unauthenticated connections has been exceeded.");
                    }
                    return message;
                }
            }

            switch (MessageIdConstant.fromId(raw[0], context)) {
                case SSH_MSG_KEXINIT:
                    return new KeyExchangeInitMessageParser(raw).parse();
                case SSH_MSG_KEX_ECDH_INIT:
                    return new EcdhKeyExchangeInitMessageParser(raw).parse();
                case SSH_MSG_KEX_ECDH_REPLY:
                    return new EcdhKeyExchangeReplyMessageParser(raw).parse();
                case SSH_MSG_KEXDH_INIT:
                    return new DhKeyExchangeInitMessageParser(raw).parse();
                case SSH_MSG_KEXDH_REPLY:
                    return new DhKeyExchangeReplyMessageParser(raw).parse();
                case SSH_MSG_KEX_DH_GEX_REQUEST_OLD:
                    return new DhGexKeyExchangeOldRequestMessageParser(raw).parse();
                case SSH_MSG_KEX_DH_GEX_REQUEST:
                    return new DhGexKeyExchangeRequestMessageParser(raw).parse();
                case SSH_MSG_KEX_DH_GEX_GROUP:
                    return new DhGexKeyExchangeGroupMessageParser(raw).parse();
                case SSH_MSG_KEX_DH_GEX_INIT:
                    return new DhGexKeyExchangeInitMessageParser(raw).parse();
                case SSH_MSG_KEX_DH_GEX_REPLY:
                    return new DhGexKeyExchangeReplyMessageParser(raw).parse();
                case SSH_MSG_KEXRSA_PUBKEY:
                    return new RsaKeyExchangePubkeyMessageParser(raw).parse();
                case SSH_MSG_KEXRSA_SECRET:
                    return new RsaKeyExchangeSecretMessageParser(raw).parse();
                case SSH_MSG_KEXRSA_DONE:
                    return new RsaKeyExchangeDoneMessageParser(raw).parse();
                case SSH_MSG_NEWKEYS:
                    return new NewKeysMessageParser(raw).parse();
                case SSH_MSG_SERVICE_REQUEST:
                    return new ServiceRequestMessageParser(raw).parse();
                case SSH_MSG_SERVICE_ACCEPT:
                    return new ServiceAcceptMessageParser(raw).parse();
                case SSH_MSG_CHANNEL_OPEN_CONFIRMATION:
                    return new ChannelOpenConfirmationMessageParser(raw).parse();
                case SSH_MSG_CHANNEL_DATA:
                    return new ChannelDataMessageParser(raw).parse();
                case SSH_MSG_CHANNEL_CLOSE:
                    return new ChannelCloseMessageParser(raw).parse();
                case SSH_MSG_CHANNEL_EOF:
                    return new ChannelEofMessageParser(raw).parse();
                case SSH_MSG_CHANNEL_EXTENDED_DATA:
                    return new ChannelExtendedDataMessageParser(raw).parse();
                case SSH_MSG_CHANNEL_FAILURE:
                    return new ChannelFailureMessageParser(raw).parse();
                case SSH_MSG_CHANNEL_OPEN_FAILURE:
                    return new ChannelOpenFailureMessageParser(raw).parse();
                case SSH_MSG_CHANNEL_OPEN:
                    return new ChannelOpenMessageParser(raw).parse();
                case SSH_MSG_CHANNEL_SUCCESS:
                    return new ChannelSuccessMessageParser(raw).parse();
                case SSH_MSG_CHANNEL_WINDOW_ADJUST:
                    return new ChannelWindowAdjustMessageParser(raw).parse();
                case SSH_MSG_DEBUG:
                    return new DebugMessageParser(raw).parse();
                case SSH_MSG_DISCONNECT:
                    return new DisconnectMessageParser(raw).parse();
                case SSH_MSG_IGNORE:
                    return new IgnoreMessageParser(raw).parse();
                case SSH_MSG_REQUEST_FAILURE:
                    return new GlobalRequestFailureMessageParser(raw).parse();
                case SSH_MSG_REQUEST_SUCCESS:
                    return new GlobalRequestSuccessMessageParser(raw).parse();
                case SSH_MSG_UNIMPLEMENTED:
                    return new UnimplementedMessageParser(raw).parse();
                case SSH_MSG_USERAUTH_REQUEST:
                    return getUserAuthRequestMessageParsing(raw);
                case SSH_MSG_USERAUTH_BANNER:
                    return new UserAuthBannerMessageParser(raw).parse();
                case SSH_MSG_USERAUTH_FAILURE:
                    return new UserAuthFailureMessageParser(raw).parse();
                case SSH_MSG_USERAUTH_SUCCESS:
                    return new UserAuthSuccessMessageParser(raw).parse();
                case SSH_MSG_CHANNEL_REQUEST:
                    return getChannelRequestMessageParsing(raw);
                case SSH_MSG_GLOBAL_REQUEST:
                    return getGlobalRequestMessageParsing(raw);
                case SSH_MSG_USERAUTH_INFO_REQUEST:
                    return new UserAuthInfoRequestMessageParser(raw).parse();
                case SSH_MSG_USERAUTH_INFO_RESPONSE:
                    return new UserAuthInfoResponseMessageParser(raw).parse();
                default:
                    LOGGER.debug(
                            "Received unimplemented Message "
                                    + MessageIdConstant.getNameById(raw[0])
                                    + " ("
                                    + raw[0]
                                    + ")");
                    return new UnknownMessageParser(raw).parse();
            }
        } catch (ParserException e) {
            LOGGER.debug("Error while Parsing, now parsing as UnknownMessage");
            return new UnknownMessageParser(raw).parse();
        }
    }

    private static ProtocolMessage<?> getUserAuthRequestMessageParsing(byte[] raw) {
        UserAuthUnknownMessage message = new UserAuthUnknownMessageParser(raw).parse();
        switch (message.getMethodName().getValue()) {
            case "none":
                return new UserAuthNoneMessageParser(raw).parse();
            case "password":
                return new UserAuthPasswordMessageParser(raw).parse();
            case "publickey":
                return new UserAuthPubkeyMessageParser(raw).parse();
            case "hostbased":
                return new UserAuthHostbasedMessageParser(raw).parse();
            case "keyboard-interactive":
                return new UserAuthKeyboardInteractiveMessageParser(raw).parse();
            case "gssapi-with-mic":
            case "gssapi-keyex":
            case "gssapi":
            case "external-keyx":
            default:
                return message;
        }
    }

    public static ProtocolMessage<?> getChannelRequestMessageParsing(byte[] raw) {
        ChannelRequestUnknownMessage message = new ChannelRequestUnknownMessageParser(raw).parse();
        String requestType = message.getRequestType().getValue();
        switch (requestType) {
            case "pty-req":
                return new ChannelRequestPtyMessageParser(raw).parse();
            case "x11-req":
                return new ChannelRequestX11MessageParser(raw).parse();
            case "env":
                return new ChannelRequestEnvMessageParser(raw).parse();
            case "shell":
                return new ChannelRequestShellMessageParser(raw).parse();
            case "exec":
                return new ChannelRequestExecMessageParser(raw).parse();
            case "subsystem":
                return new ChannelRequestSubsystemMessageParser(raw).parse();
            case "window-change":
                return new ChannelRequestWindowChangeMessageParser(raw).parse();
            case "xon-off":
                return new ChannelRequestXonXoffMessageParser(raw).parse();
            case "signal":
                return new ChannelRequestSignalMessageParser(raw).parse();
            case "exit-status":
                return new ChannelRequestExitStatusMessageParser(raw).parse();
            case "exit-signal":
                return new ChannelRequestExitSignalMessageParser(raw).parse();
            case "auth-agent-req@openssh.com":
                return new ChannelRequestAuthAgentMessageParser(raw).parse();
            default:
                LOGGER.debug(
                        "Received unimplemented message request type "
                                + MessageIdConstant.getNameById(raw[0])
                                + ":"
                                + requestType);
                return message;
        }
    }

    public static ProtocolMessage<?> getGlobalRequestMessageParsing(byte[] raw) {
        GlobalRequestUnknownMessage message = new GlobalRequestUnknownMessageParser(raw).parse();
        String globalRequestType = message.getRequestName().getValue();
        /*
        auth-agent-req@openssh.com,
        STREAMLOCAL_FORWARD_OPENSSH_COM("streamlocal-forward@openssh.com"),
        CANCEL_STREAMLOCAL_FORWARD_OPENSSH_COM("cancel-streamlocal-forward@openssh.com"),
        HOSTKEYS_00_OPENSSH_COM("hostkeys-00@openssh.com"),
        HOSTKEYS_PROVE_00_OPENSSH_COM("hostkeys-prove-00@openssh.com");*/
        switch (globalRequestType) {
            case "tcpip-forward":
                return new GlobalRequestTcpIpForwardMessageParser(raw).parse();
            case "cancel-tcpip-forward":
                return new GlobalRequestCancelTcpIpForwardMessageParser(raw).parse();
            case "no-more-sessions@openssh.com":
                return new GlobalRequestNoMoreSessionsMessageParser(raw).parse();

            default:
                LOGGER.debug(
                        "Received unimplemented global request type "
                                + MessageIdConstant.getNameById(raw[0])
                                + ":"
                                + globalRequestType);
                return message;
        }
    }
}
