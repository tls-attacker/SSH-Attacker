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

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.nio.charset.StandardCharsets;

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
                case SSH_MSG_HBR_INIT:
                    return handleHybridKeyExchangeInitMessageParsing(raw, context).parse();
                case SSH_MSG_HBR_REPLY:
                    return handleHybridKeyExchangeReplyMessageParsing(raw, context).parse();
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
                    return handleChannelOpenMessageParsing(raw);
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
                    return handleUserAuthRequestMessageParsing(raw);
                case SSH_MSG_USERAUTH_BANNER:
                    return new UserAuthBannerMessageParser(raw).parse();
                case SSH_MSG_USERAUTH_FAILURE:
                    return new UserAuthFailureMessageParser(raw).parse();
                case SSH_MSG_USERAUTH_SUCCESS:
                    return new UserAuthSuccessMessageParser(raw).parse();
                case SSH_MSG_CHANNEL_REQUEST:
                    return handleChannelRequestMessageParsing(raw);
                case SSH_MSG_GLOBAL_REQUEST:
                    return handleGlobalRequestMessageParsing(raw);
                case SSH_MSG_USERAUTH_INFO_REQUEST:
                    return new UserAuthInfoRequestMessageParser(raw).parse();
                case SSH_MSG_USERAUTH_INFO_RESPONSE:
                    return new UserAuthInfoResponseMessageParser(raw).parse();
                default:
                    LOGGER.debug(
                            "Received unimplemented Message {} ({})",
                            MessageIdConstant.getNameById(raw[0]),
                            raw[0]);
                    return new UnknownMessageParser(raw).parse();
            }
        } catch (ParserException e) {
            LOGGER.debug("Error while Parsing, now parsing as UnknownMessage", e);
            return new UnknownMessageParser(raw).parse();
        }
    }

    public static HybridKeyExchangeReplyMessageParser handleHybridKeyExchangeReplyMessageParsing(
            byte[] raw, SshContext context) {
        LOGGER.info(
                "Negotiated Hybrid Key Exchange: {}",
                context.getChooser().getKeyExchangeAlgorithm());
        switch (context.getChooser().getKeyExchangeAlgorithm()) {
                //noinspection DefaultNotLastCaseInSwitch
            default:
                LOGGER.warn(
                        "Unsupported hybrid key exchange negotiated, treating received HBR_REPLY as sntrup761x25519-sha512@openssh.com");
                // Fallthrough to next case statement intended
            case SNTRUP761_X25519:
                return new HybridKeyExchangeReplyMessageParser(
                        raw,
                        HybridKeyExchangeCombiner.POSTQUANTUM_CONCATENATE_CLASSICAL,
                        CryptoConstants.X25519_POINT_SIZE,
                        CryptoConstants.SNTRUP761_CIPHERTEXT_SIZE);
            case CURVE25519_FRODOKEM1344:
                return new HybridKeyExchangeReplyMessageParser(
                        raw,
                        HybridKeyExchangeCombiner.POSTQUANTUM_CONCATENATE_CLASSICAL,
                        CryptoConstants.X25519_POINT_SIZE,
                        CryptoConstants.FRODOKEM1344_CIPHERTEXT_SIZE);
            case SNTRUP4591761_X25519:
                return new HybridKeyExchangeReplyMessageParser(
                        raw,
                        HybridKeyExchangeCombiner.POSTQUANTUM_CONCATENATE_CLASSICAL,
                        CryptoConstants.X25519_POINT_SIZE,
                        CryptoConstants.SNTRUP4591761_CIPHERTEXT_SIZE);
            case NISTP521_FIRESABER:
                return new HybridKeyExchangeReplyMessageParser(
                        raw,
                        HybridKeyExchangeCombiner.POSTQUANTUM_CONCATENATE_CLASSICAL,
                        CryptoConstants.NISTP521_POINT_SIZE,
                        CryptoConstants.FIRESABER_CIPHERTEXT_SIZE);
            case NISTP521_KYBER1024:
                return new HybridKeyExchangeReplyMessageParser(
                        raw,
                        HybridKeyExchangeCombiner.POSTQUANTUM_CONCATENATE_CLASSICAL,
                        CryptoConstants.NISTP521_POINT_SIZE,
                        CryptoConstants.KYBER1024_CIPHERTEXT_SIZE);
        }
    }

    public static HybridKeyExchangeInitMessageParser handleHybridKeyExchangeInitMessageParsing(
            byte[] raw, SshContext context) {
        LOGGER.info(
                "Negotiated Hybrid Key Exchange: {}",
                context.getChooser().getKeyExchangeAlgorithm());
        switch (context.getChooser().getKeyExchangeAlgorithm()) {
                //noinspection DefaultNotLastCaseInSwitch
            default:
                LOGGER.warn(
                        "Unsupported hybrid key exchange negotiated, treating received HBR_INIT as sntrup761x25519-sha512@openssh.com");
                // Fallthrough to next case statement intended
            case SNTRUP761_X25519:
                return new HybridKeyExchangeInitMessageParser(
                        raw,
                        HybridKeyExchangeCombiner.POSTQUANTUM_CONCATENATE_CLASSICAL,
                        CryptoConstants.X25519_POINT_SIZE,
                        CryptoConstants.SNTRUP761_PUBLIC_KEY_SIZE);
            case SNTRUP4591761_X25519:
                return new HybridKeyExchangeInitMessageParser(
                        raw,
                        HybridKeyExchangeCombiner.POSTQUANTUM_CONCATENATE_CLASSICAL,
                        CryptoConstants.X25519_POINT_SIZE,
                        CryptoConstants.SNTRUP4591761_PUBLIC_KEY_SIZE);
            case CURVE25519_FRODOKEM1344:
                return new HybridKeyExchangeInitMessageParser(
                        raw,
                        HybridKeyExchangeCombiner.POSTQUANTUM_CONCATENATE_CLASSICAL,
                        CryptoConstants.X25519_POINT_SIZE,
                        CryptoConstants.FRODOKEM1344_PUBLIC_KEY_SIZE);
            case NISTP521_FIRESABER:
                return new HybridKeyExchangeInitMessageParser(
                        raw,
                        HybridKeyExchangeCombiner.POSTQUANTUM_CONCATENATE_CLASSICAL,
                        CryptoConstants.NISTP521_POINT_SIZE,
                        CryptoConstants.FIRESABER_PUBLIC_KEY_SIZE);
            case NISTP521_KYBER1024:
                return new HybridKeyExchangeInitMessageParser(
                        raw,
                        HybridKeyExchangeCombiner.POSTQUANTUM_CONCATENATE_CLASSICAL,
                        CryptoConstants.NISTP521_POINT_SIZE,
                        CryptoConstants.KYBER1024_PUBLIC_KEY_SIZE);
        }
    }

    private static ProtocolMessage<?> handleUserAuthRequestMessageParsing(byte[] raw) {
        UserAuthUnknownMessage message = new UserAuthUnknownMessageParser(raw).parse();
        String methodString = message.getMethodName().getValue();
        AuthenticationMethod method = AuthenticationMethod.fromName(methodString);
        switch (method) {
            case NONE:
                return new UserAuthNoneMessageParser(raw).parse();
            case PASSWORD:
                return new UserAuthPasswordMessageParser(raw).parse();
            case PUBLICKEY:
                return new UserAuthPubkeyMessageParser(raw).parse();
            case HOST_BASED:
                return new UserAuthHostbasedMessageParser(raw).parse();
            case KEYBOARD_INTERACTIVE:
                return new UserAuthKeyboardInteractiveMessageParser(raw).parse();
            default:
                LOGGER.debug(
                        "Received unimplemented user authentication method in user authentication request: {}",
                        methodString);
                return message;
        }
    }

    public static ProtocolMessage<?> handleChannelRequestMessageParsing(byte[] raw) {
        ChannelRequestUnknownMessage message = new ChannelRequestUnknownMessageParser(raw).parse();
        String requestTypeString = message.getRequestType().getValue();
        ChannelRequestType requestType = ChannelRequestType.fromName(requestTypeString);
        switch (requestType) {
            case PTY_REQ:
                return new ChannelRequestPtyMessageParser(raw).parse();
            case X11_REQ:
                return new ChannelRequestX11MessageParser(raw).parse();
            case ENV:
                return new ChannelRequestEnvMessageParser(raw).parse();
            case SHELL:
                return new ChannelRequestShellMessageParser(raw).parse();
            case EXEC:
                return new ChannelRequestExecMessageParser(raw).parse();
            case SUBSYSTEM:
                return new ChannelRequestSubsystemMessageParser(raw).parse();
            case WINDOW_CHANGE:
                return new ChannelRequestWindowChangeMessageParser(raw).parse();
            case XON_XOFF:
                return new ChannelRequestXonXoffMessageParser(raw).parse();
            case SIGNAL:
                return new ChannelRequestSignalMessageParser(raw).parse();
            case EXIT_STATUS:
                return new ChannelRequestExitStatusMessageParser(raw).parse();
            case EXIT_SIGNAL:
                return new ChannelRequestExitSignalMessageParser(raw).parse();
            case AUTH_AGENT_REQ_OPENSSH_COM:
                return new ChannelRequestAuthAgentMessageParser(raw).parse();
            default:
                LOGGER.debug(
                        "Received unimplemented channel request message type: {}",
                        requestTypeString);
                return message;
        }
    }

    public static ProtocolMessage<?> handleGlobalRequestMessageParsing(byte[] raw) {
        GlobalRequestUnknownMessage message = new GlobalRequestUnknownMessageParser(raw).parse();
        String requestTypeString = message.getRequestName().getValue();
        GlobalRequestType requestType = GlobalRequestType.fromName(requestTypeString);
        switch (requestType) {
            case TCPIP_FORWARD:
                return new GlobalRequestTcpIpForwardMessageParser(raw).parse();
            case CANCEL_TCPIP_FORWARD:
                return new GlobalRequestCancelTcpIpForwardMessageParser(raw).parse();
            case NO_MORE_SESSIONS_OPENSSH_COM:
                return new GlobalRequestNoMoreSessionsMessageParser(raw).parse();
            case HOSTKEYS_00_OPENSSH_COM:
                return new GlobalRequestOpenSshHostKeysMessageParser(raw).parse();
            default:
                LOGGER.debug(
                        "Received unimplemented global request message type: {}",
                        requestTypeString);
                return message;
        }
    }

    public static ProtocolMessage<?> handleChannelOpenMessageParsing(byte[] raw) {
        ChannelOpenUnknownMessage message = new ChannelOpenUnknownMessageParser(raw).parse();
        String channelTypeString = message.getChannelType().getValue();
        ChannelType channelType = ChannelType.fromName(channelTypeString);
        //noinspection SwitchStatementWithTooFewBranches
        switch (channelType) {
            case SESSION:
                return new ChannelOpenSessionMessageParser(raw).parse();
            default:
                LOGGER.debug(
                        "Received unimplemented channel open message type: {}", channelTypeString);
                return message;
        }
    }
}
