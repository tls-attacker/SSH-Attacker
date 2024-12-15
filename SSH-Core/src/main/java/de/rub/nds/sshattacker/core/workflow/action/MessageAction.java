/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.workflow.action;

import de.rub.nds.modifiablevariable.HoldsModifiableVariable;
import de.rub.nds.sshattacker.core.connection.AliasedConnection;
import de.rub.nds.sshattacker.core.data.sftp.message.SftpInitMessage;
import de.rub.nds.sshattacker.core.data.sftp.message.SftpUnknownMessage;
import de.rub.nds.sshattacker.core.data.sftp.message.SftpVersionMessage;
import de.rub.nds.sshattacker.core.data.sftp.message.extended_request.*;
import de.rub.nds.sshattacker.core.data.sftp.message.extended_response.*;
import de.rub.nds.sshattacker.core.data.sftp.message.request.*;
import de.rub.nds.sshattacker.core.data.sftp.message.response.*;
import de.rub.nds.sshattacker.core.protocol.authentication.message.*;
import de.rub.nds.sshattacker.core.protocol.common.ProtocolMessage;
import de.rub.nds.sshattacker.core.protocol.connection.message.*;
import de.rub.nds.sshattacker.core.protocol.transport.message.*;
import jakarta.xml.bind.annotation.XmlElement;
import jakarta.xml.bind.annotation.XmlElementWrapper;
import jakarta.xml.bind.annotation.XmlElements;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

public abstract class MessageAction extends ConnectionBoundAction {

    @HoldsModifiableVariable
    @XmlElementWrapper
    @XmlElements({
        // Authentication Protocol Messages
        @XmlElement(type = UserAuthBannerMessage.class, name = "UserAuthBanner"),
        @XmlElement(type = UserAuthFailureMessage.class, name = "UserAuthFailure"),
        @XmlElement(type = UserAuthHostbasedMessage.class, name = "UserAuthHostbased"),
        @XmlElement(type = UserAuthInfoRequestMessage.class, name = "UserAuthInfoRequest"),
        @XmlElement(type = UserAuthInfoResponseMessage.class, name = "UserAuthInfoResponse"),
        @XmlElement(
                type = UserAuthKeyboardInteractiveMessage.class,
                name = "UserAuthKeyboardInteractive"),
        @XmlElement(type = UserAuthNoneMessage.class, name = "UserAuthNone"),
        @XmlElement(type = UserAuthPasswordMessage.class, name = "UserAuthPassword"),
        @XmlElement(type = UserAuthPkOkMessage.class, name = "UserAuthPkOk"),
        @XmlElement(type = UserAuthPubkeyMessage.class, name = "UserAuthPubkey"),
        @XmlElement(type = UserAuthRequestMessage.class, name = "UserAuthRequest"),
        @XmlElement(type = UserAuthSuccessMessage.class, name = "UserAuthSuccess"),
        @XmlElement(type = UserAuthUnknownMessage.class, name = "UserAuthUnknownRequest"),
        // Connection Protocol Messages
        @XmlElement(type = ChannelCloseMessage.class, name = "ChannelClose"),
        @XmlElement(type = ChannelDataMessage.class, name = "ChannelData"),
        @XmlElement(type = ChannelEofMessage.class, name = "ChannelEof"),
        @XmlElement(type = ChannelExtendedDataMessage.class, name = "ChannelExtendedData"),
        @XmlElement(type = ChannelFailureMessage.class, name = "ChannelFailure"),
        @XmlElement(type = ChannelOpenConfirmationMessage.class, name = "ChannelOpenConfirmation"),
        @XmlElement(type = ChannelOpenFailureMessage.class, name = "ChannelOpenFailure"),
        @XmlElement(type = ChannelOpenSessionMessage.class, name = "ChannelOpenSession"),
        @XmlElement(type = ChannelOpenUnknownMessage.class, name = "ChannelOpenUnknown"),
        @XmlElement(type = ChannelRequestAuthAgentMessage.class, name = "ChannelRequestAuthAgent"),
        @XmlElement(type = ChannelRequestBreakMessage.class, name = "ChannelRequestBreak"),
        @XmlElement(type = ChannelRequestEnvMessage.class, name = "ChannelRequestEnv"),
        @XmlElement(type = ChannelRequestExecMessage.class, name = "ChannelRequestExec"),
        @XmlElement(
                type = ChannelRequestExitSignalMessage.class,
                name = "ChannelRequestExitSignal"),
        @XmlElement(
                type = ChannelRequestExitStatusMessage.class,
                name = "ChannelRequestExitStatus"),
        @XmlElement(type = ChannelRequestPtyMessage.class, name = "ChannelRequestPty"),
        @XmlElement(type = ChannelRequestShellMessage.class, name = "ChannelRequestShell"),
        @XmlElement(type = ChannelRequestSignalMessage.class, name = "ChannelRequestSignal"),
        @XmlElement(type = ChannelRequestSubsystemMessage.class, name = "ChannelRequestSubsystem"),
        @XmlElement(type = ChannelRequestUnknownMessage.class, name = "ChannelRequestUnknown"),
        @XmlElement(
                type = ChannelRequestWindowChangeMessage.class,
                name = "ChannelRequestWindowChange"),
        @XmlElement(type = ChannelRequestX11Message.class, name = "ChannelRequestX11"),
        @XmlElement(type = ChannelRequestXonXoffMessage.class, name = "ChannelRequestXonXoff"),
        @XmlElement(type = ChannelSuccessMessage.class, name = "ChannelSuccess"),
        @XmlElement(type = ChannelWindowAdjustMessage.class, name = "ChannelWindowAdjust"),
        @XmlElement(
                type = GlobalRequestCancelTcpIpForwardMessage.class,
                name = "GlobalRequestCancelTcpIpForward"),
        @XmlElement(type = GlobalRequestFailureMessage.class, name = "GlobalRequestFailure"),
        @XmlElement(
                type = GlobalRequestNoMoreSessionsMessage.class,
                name = "GlobalRequestNoMoreSessions"),
        @XmlElement(type = GlobalRequestSuccessMessage.class, name = "GlobalRequestSuccess"),
        @XmlElement(
                type = GlobalRequestTcpIpForwardMessage.class,
                name = "GlobalRequestTcpIpForward"),
        @XmlElement(
                type = GlobalRequestOpenSshHostKeysMessage.class,
                name = "GlobalRequestOpenSshHostKeys"),
        @XmlElement(type = GlobalRequestUnknownMessage.class, name = "GlobalRequestUnknown"),
        // Transport Layer Protocol Messages
        @XmlElement(type = DebugMessage.class, name = "DebugMessage"),
        @XmlElement(type = DhGexKeyExchangeGroupMessage.class, name = "DhGexKeyExchangeGroup"),
        @XmlElement(type = DhGexKeyExchangeInitMessage.class, name = "DhGexKeyExchangeInit"),
        @XmlElement(
                type = DhGexKeyExchangeOldRequestMessage.class,
                name = "DhGexKeyExchangeOldRequest"),
        @XmlElement(type = DhGexKeyExchangeReplyMessage.class, name = "DhGexKeyExchangeReply"),
        @XmlElement(type = DhGexKeyExchangeRequestMessage.class, name = "DhGexKeyExchangeRequest"),
        @XmlElement(type = DhKeyExchangeInitMessage.class, name = "DhKeyExchangeInit"),
        @XmlElement(type = DhKeyExchangeReplyMessage.class, name = "DhKeyExchangeReply"),
        @XmlElement(type = DisconnectMessage.class, name = "DisconnectMessage"),
        @XmlElement(type = EcdhKeyExchangeInitMessage.class, name = "EcdhKeyExchangeInit"),
        @XmlElement(type = EcdhKeyExchangeReplyMessage.class, name = "EcdhKeyExchangeReply"),
        @XmlElement(type = ExtensionInfoMessage.class, name = "ExtensionInfo"),
        @XmlElement(type = HybridKeyExchangeInitMessage.class, name = "HybridKeyExchangeInit"),
        @XmlElement(type = HybridKeyExchangeReplyMessage.class, name = "HybridKeyExchangeReply"),
        @XmlElement(type = IgnoreMessage.class, name = "IgnoreMessage"),
        @XmlElement(type = KeyExchangeInitMessage.class, name = "KeyExchangeInit"),
        @XmlElement(type = NewCompressMessage.class, name = "NewCompress"),
        @XmlElement(type = NewKeysMessage.class, name = "NewKeys"),
        @XmlElement(type = PingMessage.class, name = "Ping"),
        @XmlElement(type = PongMessage.class, name = "Pong"),
        @XmlElement(type = RsaKeyExchangeDoneMessage.class, name = "RsaKeyExchangeDone"),
        @XmlElement(type = RsaKeyExchangePubkeyMessage.class, name = "RsaKeyExchangePubkey"),
        @XmlElement(type = RsaKeyExchangeSecretMessage.class, name = "RsaKeyExchangeSecret"),
        @XmlElement(type = ServiceAcceptMessage.class, name = "ServiceAccept"),
        @XmlElement(type = ServiceRequestMessage.class, name = "ServiceRequest"),
        @XmlElement(type = UnimplementedMessage.class, name = "UnimplementedMessage"),
        @XmlElement(type = UnknownMessage.class, name = "UnknownMessage"),
        @XmlElement(type = VersionExchangeMessage.class, name = "VersionExchange"),
        @XmlElement(type = AsciiMessage.class, name = "AsciiMessage"),
        // SFTP
        @XmlElement(type = SftpInitMessage.class, name = "SftpInit"),
        @XmlElement(
                type = SftpRequestCheckFileHandleMessage.class,
                name = "SftpRequestCheckFileHandle"),
        @XmlElement(
                type = SftpRequestCheckFileNameMessage.class,
                name = "SftpRequestCheckFileName"),
        @XmlElement(type = SftpRequestCloseMessage.class, name = "SftpRequestClose"),
        @XmlElement(type = SftpRequestCopyDataMessage.class, name = "SftpRequestCopyData"),
        @XmlElement(type = SftpRequestCopyFileMessage.class, name = "SftpRequestCopyFile"),
        @XmlElement(type = SftpRequestExpandPathMessage.class, name = "SftpRequestExpandPath"),
        @XmlElement(type = SftpRequestFileSetStatMessage.class, name = "SftpRequestFileSetStat"),
        @XmlElement(type = SftpRequestFileStatMessage.class, name = "SftpRequestFileStat"),
        @XmlElement(type = SftpRequestFileStatVfsMessage.class, name = "SftpRequestFileStatVfs"),
        @XmlElement(type = SftpRequestFileSyncMessage.class, name = "SftpRequestFileSync"),
        @XmlElement(
                type = SftpRequestGetTempFolderMessage.class,
                name = "SftpRequestGetTempFolder"),
        @XmlElement(type = SftpRequestHardlinkMessage.class, name = "SftpRequestHardlink"),
        @XmlElement(
                type = SftpRequestHomeDirectoryMessage.class,
                name = "SftpRequestHomeDirectory"),
        @XmlElement(type = SftpRequestLimitsMessage.class, name = "SftpRequestLimits"),
        @XmlElement(type = SftpRequestLinkSetStatMessage.class, name = "SftpRequestLinkSetStat"),
        @XmlElement(type = SftpRequestLinkStatMessage.class, name = "SftpRequestLinkStat"),
        @XmlElement(type = SftpRequestMakeDirMessage.class, name = "SftpRequestMakeDir"),
        @XmlElement(
                type = SftpRequestMakeTempFolderMessage.class,
                name = "SftpRequestMakeTempFolder"),
        @XmlElement(type = SftpRequestOpenDirMessage.class, name = "SftpRequestOpenDir"),
        @XmlElement(type = SftpRequestOpenMessage.class, name = "SftpRequestOpen"),
        @XmlElement(type = SftpRequestPosixRenameMessage.class, name = "SftpRequestPosixRename"),
        @XmlElement(type = SftpRequestReadDirMessage.class, name = "SftpRequestReadDir"),
        @XmlElement(type = SftpRequestReadLinkMessage.class, name = "SftpRequestReadLink"),
        @XmlElement(type = SftpRequestReadMessage.class, name = "SftpRequestRead"),
        @XmlElement(type = SftpRequestRealPathMessage.class, name = "SftpRequestRealPath"),
        @XmlElement(type = SftpRequestRemoveMessage.class, name = "SftpRequestRemove"),
        @XmlElement(type = SftpRequestRenameMessage.class, name = "SftpRequestRename"),
        @XmlElement(type = SftpRequestRemoveDirMessage.class, name = "SftpRequestRmdir"),
        @XmlElement(type = SftpRequestSetStatMessage.class, name = "SftpRequestSetStat"),
        @XmlElement(
                type = SftpRequestSpaceAvailableMessage.class,
                name = "SftpRequestSpaceAvailable"),
        @XmlElement(type = SftpRequestStatMessage.class, name = "SftpRequestStat"),
        @XmlElement(type = SftpRequestStatVfsMessage.class, name = "SftpRequestStatVfs"),
        @XmlElement(type = SftpRequestSymbolicLinkMessage.class, name = "SftpRequestSymbolicLink"),
        @XmlElement(type = SftpRequestUnknownMessage.class, name = "SftpRequestUnknown"),
        @XmlElement(
                type = SftpRequestUsersGroupsByIdMessage.class,
                name = "SftpRequestUsersGroupsById"),
        @XmlElement(type = SftpRequestVendorIdMessage.class, name = "SftpRequestVendorId"),
        @XmlElement(type = SftpRequestWithHandleMessage.class, name = "SftpRequestWithHandle"),
        @XmlElement(type = SftpRequestWithPathMessage.class, name = "SftpRequestWithPath"),
        @XmlElement(type = SftpRequestWriteMessage.class, name = "SftpRequestWrite"),
        @XmlElement(type = SftpResponseAttributesMessage.class, name = "SftpResponseAttributes"),
        @XmlElement(type = SftpResponseCheckFileMessage.class, name = "SftpResponseCheckFile"),
        @XmlElement(type = SftpResponseDataMessage.class, name = "SftpResponseData"),
        @XmlElement(type = SftpResponseHandleMessage.class, name = "SftpResponseHandle"),
        @XmlElement(type = SftpResponseLimitsMessage.class, name = "SftpResponseLimits"),
        @XmlElement(type = SftpResponseNameMessage.class, name = "SftpResponseName"),
        @XmlElement(
                type = SftpResponseSpaceAvailableMessage.class,
                name = "SftpResponseSpaceAvailable"),
        @XmlElement(type = SftpResponseStatusMessage.class, name = "SftpResponseStatus"),
        @XmlElement(type = SftpResponseStatVfsMessage.class, name = "SftpResponseStatVfs"),
        @XmlElement(type = SftpResponseUnknownMessage.class, name = "SftpResponseUnknown"),
        @XmlElement(
                type = SftpResponseUsersGroupsByIdMessage.class,
                name = "SftpResponseUsersGroupsById"),
        @XmlElement(type = SftpUnknownMessage.class, name = "SftpUnknown"),
        @XmlElement(type = SftpVersionMessage.class, name = "SftpVersion"),
        // SFTP V4
        @XmlElement(type = SftpRequestTextSeekMessage.class, name = "SftpRequestTextSeek")
    })
    protected ArrayList<ProtocolMessage<?>> messages = new ArrayList<>();

    protected MessageAction() {
        super(AliasedConnection.DEFAULT_CONNECTION_ALIAS);
    }

    protected MessageAction(ArrayList<ProtocolMessage<?>> messages) {
        super(AliasedConnection.DEFAULT_CONNECTION_ALIAS);
        this.messages = messages;
    }

    protected MessageAction(List<ProtocolMessage<?>> messages) {
        this(new ArrayList<>(messages));
    }

    protected MessageAction(ProtocolMessage<?>... messages) {
        this(Arrays.asList(messages));
    }

    protected MessageAction(String connectionAlias) {
        super(connectionAlias);
    }

    protected MessageAction(String connectionAlias, ArrayList<ProtocolMessage<?>> messages) {
        super(connectionAlias);
        this.messages = messages;
    }

    protected MessageAction(String connectionAlias, List<ProtocolMessage<?>> messages) {
        this(connectionAlias, new ArrayList<>(messages));
    }

    protected MessageAction(String connectionAlias, ProtocolMessage<?>... messages) {
        this(connectionAlias, Arrays.asList(messages));
    }

    protected MessageAction(MessageAction other) {
        super(other);
        if (other.messages != null) {
            messages = new ArrayList<>(other.messages.size());
            for (ProtocolMessage<?> item : other.messages) {
                messages.add(item != null ? item.createCopy() : null);
            }
        }
    }

    @Override
    public abstract MessageAction createCopy();

    public static String getReadableString(ProtocolMessage<?>... messages) {
        return getReadableString(Arrays.asList(messages));
    }

    public static String getReadableString(List<ProtocolMessage<?>> messages) {
        return getReadableString(messages, false);
    }

    public static String getReadableString(List<ProtocolMessage<?>> messages, Boolean verbose) {
        if (messages == null || messages.isEmpty()) {
            return "";
        }
        StringBuilder builder = new StringBuilder();

        for (int i = 0; i < messages.size(); i++) {
            if (i > 0) {
                builder.append(", ");
            }
            ProtocolMessage<?> message = messages.get(i);
            if (verbose) {
                builder.append(message.toString());
            } else {
                builder.append(message.toCompactString());
            }
            if (!message.isRequired()) {
                builder.append("*");
            }
        }
        return builder.toString();
    }

    @Override
    public void normalize() {
        super.normalize();
        initEmptyLists();
    }

    @Override
    public void normalize(SshAction defaultAction) {
        super.normalize(defaultAction);
        initEmptyLists();
    }

    @Override
    public void filter() {
        super.filter();
        stripEmptyLists();
    }

    @Override
    public void filter(SshAction defaultAction) {
        super.filter(defaultAction);
        stripEmptyLists();
    }

    protected void stripEmptyLists() {
        if (messages == null || messages.isEmpty()) {
            messages = null;
        }
    }

    protected void initEmptyLists() {
        if (messages == null) {
            messages = new ArrayList<>();
        }
    }
}
