/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.common;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.sshattacker.core.constants.*;
import de.rub.nds.sshattacker.core.exceptions.ParserException;
import de.rub.nds.sshattacker.core.packet.AbstractPacket;
import de.rub.nds.sshattacker.core.packet.BlobPacket;
import de.rub.nds.sshattacker.core.protocol.authentication.message.*;
import de.rub.nds.sshattacker.core.protocol.authentication.parser.*;
import de.rub.nds.sshattacker.core.protocol.connection.message.ChannelOpenUnknownMessage;
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

    protected ProtocolMessageParser(byte[] array) {
        super(array);
    }

    protected ProtocolMessageParser(byte[] array, int startPosition) {
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
                "Complete message bytes parsed: {}",
                ArrayConverter.bytesToHexString(message.getCompleteResultingMessage().getValue()));
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
                    AsciiMessage message = new AsciiMessageParser(raw).parse();

                    // If we know what the text message means we can print a
                    // human-readable warning to the log. The following
                    // messages are sent by OpenSSH.
                    String messageText = message.getText().getValue();
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

            return switch (MessageIdConstant.fromId(raw[0], context)) {
                case SSH_MSG_KEXINIT -> new KeyExchangeInitMessageParser(raw).parse();
                case SSH_MSG_KEX_ECDH_INIT -> new EcdhKeyExchangeInitMessageParser(raw).parse();
                case SSH_MSG_KEX_ECDH_REPLY -> new EcdhKeyExchangeReplyMessageParser(raw).parse();
                case SSH_MSG_KEXDH_INIT -> new DhKeyExchangeInitMessageParser(raw).parse();
                case SSH_MSG_KEXDH_REPLY -> new DhKeyExchangeReplyMessageParser(raw).parse();
                case SSH_MSG_HBR_INIT -> new HybridKeyExchangeInitMessageParser(raw).parse();
                case SSH_MSG_HBR_REPLY -> new HybridKeyExchangeReplyMessageParser(raw).parse();
                case SSH_MSG_KEX_DH_GEX_REQUEST_OLD ->
                        new DhGexKeyExchangeOldRequestMessageParser(raw).parse();
                case SSH_MSG_KEX_DH_GEX_REQUEST ->
                        new DhGexKeyExchangeRequestMessageParser(raw).parse();
                case SSH_MSG_KEX_DH_GEX_GROUP ->
                        new DhGexKeyExchangeGroupMessageParser(raw).parse();
                case SSH_MSG_KEX_DH_GEX_INIT -> new DhGexKeyExchangeInitMessageParser(raw).parse();
                case SSH_MSG_KEX_DH_GEX_REPLY ->
                        new DhGexKeyExchangeReplyMessageParser(raw).parse();
                case SSH_MSG_KEXRSA_PUBKEY -> new RsaKeyExchangePubkeyMessageParser(raw).parse();
                case SSH_MSG_KEXRSA_SECRET -> new RsaKeyExchangeSecretMessageParser(raw).parse();
                case SSH_MSG_KEXRSA_DONE -> new RsaKeyExchangeDoneMessageParser(raw).parse();
                case SSH_MSG_NEWKEYS -> new NewKeysMessageParser(raw).parse();
                case SSH_MSG_EXT_INFO -> new ExtensionInfoMessageParser(raw).parse();
                case SSH_MSG_NEWCOMPRESS -> new NewCompressMessageParser(raw).parse();
                case SSH_MSG_PING -> new PingMessageParser(raw).parse();
                case SSH_MSG_PONG -> new PongMessageParser(raw).parse();
                case SSH_MSG_SERVICE_REQUEST -> new ServiceRequestMessageParser(raw).parse();
                case SSH_MSG_SERVICE_ACCEPT -> new ServiceAcceptMessageParser(raw).parse();
                case SSH_MSG_CHANNEL_OPEN_CONFIRMATION ->
                        new ChannelOpenConfirmationMessageParser(raw).parse();
                case SSH_MSG_CHANNEL_DATA -> new ChannelDataMessageParser(raw).parse();
                case SSH_MSG_CHANNEL_CLOSE -> new ChannelCloseMessageParser(raw).parse();
                case SSH_MSG_CHANNEL_EOF -> new ChannelEofMessageParser(raw).parse();
                case SSH_MSG_CHANNEL_EXTENDED_DATA ->
                        new ChannelExtendedDataMessageParser(raw).parse();
                case SSH_MSG_CHANNEL_FAILURE -> new ChannelFailureMessageParser(raw).parse();
                case SSH_MSG_CHANNEL_OPEN_FAILURE ->
                        new ChannelOpenFailureMessageParser(raw).parse();
                case SSH_MSG_CHANNEL_OPEN -> handleChannelOpenMessageParsing(raw);
                case SSH_MSG_CHANNEL_SUCCESS -> new ChannelSuccessMessageParser(raw).parse();
                case SSH_MSG_CHANNEL_WINDOW_ADJUST ->
                        new ChannelWindowAdjustMessageParser(raw).parse();
                case SSH_MSG_DEBUG -> new DebugMessageParser(raw).parse();
                case SSH_MSG_DISCONNECT -> new DisconnectMessageParser(raw).parse();
                case SSH_MSG_IGNORE -> new IgnoreMessageParser(raw).parse();
                case SSH_MSG_REQUEST_FAILURE -> new GlobalRequestFailureMessageParser(raw).parse();
                case SSH_MSG_REQUEST_SUCCESS -> new GlobalRequestSuccessMessageParser(raw).parse();
                case SSH_MSG_UNIMPLEMENTED -> new UnimplementedMessageParser(raw).parse();
                case SSH_MSG_USERAUTH_REQUEST -> handleUserAuthRequestMessageParsing(raw);
                case SSH_MSG_USERAUTH_BANNER -> new UserAuthBannerMessageParser(raw).parse();
                case SSH_MSG_USERAUTH_FAILURE -> new UserAuthFailureMessageParser(raw).parse();
                case SSH_MSG_USERAUTH_SUCCESS -> new UserAuthSuccessMessageParser(raw).parse();
                case SSH_MSG_CHANNEL_REQUEST -> handleChannelRequestMessageParsing(raw);
                case SSH_MSG_GLOBAL_REQUEST -> handleGlobalRequestMessageParsing(raw);
                case SSH_MSG_USERAUTH_INFO_REQUEST ->
                        new UserAuthInfoRequestMessageParser(raw).parse();
                case SSH_MSG_USERAUTH_INFO_RESPONSE ->
                        new UserAuthInfoResponseMessageParser(raw).parse();
                default -> {
                    LOGGER.debug(
                            "Received unimplemented Message {} ({})",
                            MessageIdConstant.getNameById(raw[0]),
                            raw[0]);
                    yield new UnknownMessageParser(raw).parse();
                }
            };
        } catch (ParserException e) {
            LOGGER.debug("Error while Parsing, now parsing as UnknownMessage", e);
            return new UnknownMessageParser(raw).parse();
        }
    }

    private static ProtocolMessage<?> handleUserAuthRequestMessageParsing(byte[] raw) {
        UserAuthUnknownMessage message = new UserAuthUnknownMessageParser(raw).parse();
        String methodString = message.getMethodName().getValue();
        AuthenticationMethod method = AuthenticationMethod.fromName(methodString);
        return switch (method) {
            case NONE -> new UserAuthNoneMessageParser(raw).parse();
            case PASSWORD -> new UserAuthPasswordMessageParser(raw).parse();
            case PUBLICKEY -> new UserAuthPubkeyMessageParser(raw).parse();
            case HOST_BASED -> new UserAuthHostbasedMessageParser(raw).parse();
            case KEYBOARD_INTERACTIVE -> new UserAuthKeyboardInteractiveMessageParser(raw).parse();
            default -> {
                LOGGER.debug(
                        "Received unimplemented user authentication method in user authentication request: {}",
                        methodString);
                yield message;
            }
        };
    }

    public static ProtocolMessage<?> handleChannelRequestMessageParsing(byte[] raw) {
        ChannelRequestUnknownMessage message = new ChannelRequestUnknownMessageParser(raw).parse();
        String requestTypeString = message.getRequestType().getValue();
        ChannelRequestType requestType = ChannelRequestType.fromName(requestTypeString);
        return switch (requestType) {
            case PTY_REQ -> new ChannelRequestPtyMessageParser(raw).parse();
            case X11_REQ -> new ChannelRequestX11MessageParser(raw).parse();
            case ENV -> new ChannelRequestEnvMessageParser(raw).parse();
            case SHELL -> new ChannelRequestShellMessageParser(raw).parse();
            case EXEC -> new ChannelRequestExecMessageParser(raw).parse();
            case SUBSYSTEM -> new ChannelRequestSubsystemMessageParser(raw).parse();
            case WINDOW_CHANGE -> new ChannelRequestWindowChangeMessageParser(raw).parse();
            case XON_XOFF -> new ChannelRequestXonXoffMessageParser(raw).parse();
            case SIGNAL -> new ChannelRequestSignalMessageParser(raw).parse();
            case EXIT_STATUS -> new ChannelRequestExitStatusMessageParser(raw).parse();
            case EXIT_SIGNAL -> new ChannelRequestExitSignalMessageParser(raw).parse();
            case AUTH_AGENT_REQ_OPENSSH_COM ->
                    new ChannelRequestAuthAgentMessageParser(raw).parse();
            default -> {
                LOGGER.debug(
                        "Received unimplemented channel request message type: {}",
                        requestTypeString);
                yield message;
            }
        };
    }

    public static ProtocolMessage<?> handleGlobalRequestMessageParsing(byte[] raw) {
        GlobalRequestUnknownMessage message = new GlobalRequestUnknownMessageParser(raw).parse();
        String requestTypeString = message.getRequestName().getValue();
        GlobalRequestType requestType = GlobalRequestType.fromName(requestTypeString);
        return switch (requestType) {
            case TCPIP_FORWARD -> new GlobalRequestTcpIpForwardMessageParser(raw).parse();
            case CANCEL_TCPIP_FORWARD ->
                    new GlobalRequestCancelTcpIpForwardMessageParser(raw).parse();
            case NO_MORE_SESSIONS_OPENSSH_COM ->
                    new GlobalRequestNoMoreSessionsMessageParser(raw).parse();
            case HOSTKEYS_00_OPENSSH_COM ->
                    new GlobalRequestOpenSshHostKeysMessageParser(raw).parse();
            default -> {
                LOGGER.debug(
                        "Received unimplemented global request message type: {}",
                        requestTypeString);
                yield message;
            }
        };
    }

    public static ProtocolMessage<?> handleChannelOpenMessageParsing(byte[] raw) {
        ChannelOpenUnknownMessage message = new ChannelOpenUnknownMessageParser(raw).parse();
        String channelTypeString = message.getChannelType().getValue();
        ChannelType channelType = ChannelType.fromName(channelTypeString);
        //noinspection SwitchStatementWithTooFewBranches
        return switch (channelType) {
            case SESSION -> new ChannelOpenSessionMessageParser(raw).parse();
            default -> {
                LOGGER.debug(
                        "Received unimplemented channel open message type: {}", channelTypeString);
                yield message;
            }
        };
    }
}
