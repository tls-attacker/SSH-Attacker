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
import de.rub.nds.sshattacker.core.layer.*;
import de.rub.nds.sshattacker.core.layer.constant.ImplementedLayers;
import de.rub.nds.sshattacker.core.layer.context.SshContext;
import de.rub.nds.sshattacker.core.packet.AbstractPacket;
import de.rub.nds.sshattacker.core.protocol.authentication.message.*;
import de.rub.nds.sshattacker.core.protocol.common.ProtocolMessage;
import de.rub.nds.sshattacker.core.protocol.connection.message.*;
import de.rub.nds.sshattacker.core.protocol.ssh1.message.ServerPublicKeyMessage;
import de.rub.nds.sshattacker.core.protocol.ssh1.message.VersionExchangeMessageSSHV1;
import de.rub.nds.sshattacker.core.protocol.transport.message.*;
import jakarta.xml.bind.annotation.XmlElement;
import jakarta.xml.bind.annotation.XmlElementWrapper;
import jakarta.xml.bind.annotation.XmlElements;
import jakarta.xml.bind.annotation.XmlTransient;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedList;
import java.util.List;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public abstract class MessageAction extends ConnectionBoundAction {

    private static final Logger LOGGER = LogManager.getLogger();

    @HoldsModifiableVariable
    @XmlElementWrapper
    @XmlElements(
            value = {
                // Authentication Protocol Messages
                @XmlElement(type = UserAuthBannerMessage.class, name = "UserAuthBanner"),
                @XmlElement(type = UserAuthFailureMessage.class, name = "UserAuthFailure"),
                @XmlElement(type = UserAuthHostbasedMessage.class, name = "UserAuthHostbased"),
                @XmlElement(type = UserAuthInfoRequestMessage.class, name = "UserAuthInfoRequest"),
                @XmlElement(
                        type = UserAuthInfoResponseMessage.class,
                        name = "UserAuthInfoResponse"),
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
                @XmlElement(
                        type = ChannelOpenConfirmationMessage.class,
                        name = "ChannelOpenConfirmation"),
                @XmlElement(type = ChannelOpenFailureMessage.class, name = "ChannelOpenFailure"),
                @XmlElement(type = ChannelOpenSessionMessage.class, name = "ChannelOpenSession"),
                @XmlElement(type = ChannelOpenUnknownMessage.class, name = "ChannelOpenUnknown"),
                @XmlElement(
                        type = ChannelRequestAuthAgentMessage.class,
                        name = "ChannelRequestAuthAgent"),
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
                @XmlElement(
                        type = ChannelRequestSignalMessage.class,
                        name = "ChannelRequestSignal"),
                @XmlElement(
                        type = ChannelRequestSubsystemMessage.class,
                        name = "ChannelRequestSubsystem"),
                @XmlElement(
                        type = ChannelRequestUnknownMessage.class,
                        name = "ChannelRequestUnknown"),
                @XmlElement(
                        type = ChannelRequestWindowChangeMessage.class,
                        name = "ChannelRequestWindowChange"),
                @XmlElement(type = ChannelRequestX11Message.class, name = "ChannelRequestX11"),
                @XmlElement(
                        type = ChannelRequestXonXoffMessage.class,
                        name = "ChannelRequestXonXoff"),
                @XmlElement(type = ChannelSuccessMessage.class, name = "ChannelSuccess"),
                @XmlElement(type = ChannelWindowAdjustMessage.class, name = "ChannelWindowAdjust"),
                @XmlElement(
                        type = GlobalRequestCancelTcpIpForwardMessage.class,
                        name = "GlobalRequestCancelTcpIpForward"),
                @XmlElement(
                        type = GlobalRequestFailureMessage.class,
                        name = "GlobalRequestFailure"),
                @XmlElement(
                        type = GlobalRequestNoMoreSessionsMessage.class,
                        name = "GlobalRequestNoMoreSessions"),
                @XmlElement(
                        type = GlobalRequestSuccessMessage.class,
                        name = "GlobalRequestSuccess"),
                @XmlElement(
                        type = GlobalRequestTcpIpForwardMessage.class,
                        name = "GlobalRequestTcpIpForward"),
                @XmlElement(
                        type = GlobalRequestOpenSshHostKeysMessage.class,
                        name = "GlobalRequestOpenSshHostKeys"),
                @XmlElement(
                        type = GlobalRequestUnknownMessage.class,
                        name = "GlobalRequestUnknown"),
                // Transport Layer Protocol Messages
                @XmlElement(type = DebugMessage.class, name = "DebugMessage"),
                @XmlElement(
                        type = DhGexKeyExchangeGroupMessage.class,
                        name = "DhGexKeyExchangeGroup"),
                @XmlElement(
                        type = DhGexKeyExchangeInitMessage.class,
                        name = "DhGexKeyExchangeInit"),
                @XmlElement(
                        type = DhGexKeyExchangeOldRequestMessage.class,
                        name = "DhGexKeyExchangeOldRequest"),
                @XmlElement(
                        type = DhGexKeyExchangeReplyMessage.class,
                        name = "DhGexKeyExchangeReply"),
                @XmlElement(
                        type = DhGexKeyExchangeRequestMessage.class,
                        name = "DhGexKeyExchangeRequest"),
                @XmlElement(type = DhKeyExchangeInitMessage.class, name = "DhKeyExchangeInit"),
                @XmlElement(type = DhKeyExchangeReplyMessage.class, name = "DhKeyExchangeReply"),
                @XmlElement(type = DisconnectMessage.class, name = "DisconnectMessage"),
                @XmlElement(type = EcdhKeyExchangeInitMessage.class, name = "EcdhKeyExchangeInit"),
                @XmlElement(
                        type = EcdhKeyExchangeReplyMessage.class,
                        name = "EcdhKeyExchangeReply"),
                @XmlElement(
                        type = HybridKeyExchangeInitMessage.class,
                        name = "HybridKeyExchangeInit"),
                @XmlElement(
                        type = HybridKeyExchangeReplyMessage.class,
                        name = "HybridKeyExchangeReply"),
                @XmlElement(type = IgnoreMessage.class, name = "IgnoreMessage"),
                @XmlElement(type = KeyExchangeInitMessage.class, name = "KeyExchangeInit"),
                @XmlElement(type = NewKeysMessage.class, name = "NewKeys"),
                @XmlElement(type = RsaKeyExchangeDoneMessage.class, name = "RsaKeyExchangeDone"),
                @XmlElement(
                        type = RsaKeyExchangePubkeyMessage.class,
                        name = "RsaKeyExchangePubkey"),
                @XmlElement(
                        type = RsaKeyExchangeSecretMessage.class,
                        name = "RsaKeyExchangeSecret"),
                @XmlElement(type = ServiceAcceptMessage.class, name = "ServiceAccept"),
                @XmlElement(type = ServiceRequestMessage.class, name = "ServiceRequest"),
                @XmlElement(type = UnimplementedMessage.class, name = "UnimplementedMessage"),
                @XmlElement(type = UnknownMessage.class, name = "UnknownMessage"),
                @XmlElement(type = VersionExchangeMessage.class, name = "VersionExchange"),
                @XmlElement(type = AsciiMessage.class, name = "AsciiMessage"),
                @XmlElement(type = VersionExchangeMessageSSHV1.class, name = "VersionExchangeSSH1"),
                @XmlElement(type = ServerPublicKeyMessage.class, name = "PublicKeyMessageSSH1")
            })
    protected List<ProtocolMessage<?>> messages = new ArrayList<>();

    protected List<AbstractPacket> packets = new ArrayList<>();

    @XmlTransient private LayerStackProcessingResult layerStackProcessingResult;

    // @XmlTransient protected final ReceiveMessageHelper receiveMessageHelper;

    // @XmlTransient protected final SendMessageHelper sendMessageHelper;

    public MessageAction() {
        super(AliasedConnection.DEFAULT_CONNECTION_ALIAS);
        /*receiveMessageHelper = new ReceiveMessageHelper();
        sendMessageHelper = new SendMessageHelper();*/
    }

    public MessageAction(List<ProtocolMessage<?>> messages) {
        super(AliasedConnection.DEFAULT_CONNECTION_ALIAS);
        this.messages = new ArrayList<>(messages);
        /*receiveMessageHelper = new ReceiveMessageHelper();
        sendMessageHelper = new SendMessageHelper();*/
    }

    public MessageAction(ProtocolMessage<?>... messages) {
        super(AliasedConnection.DEFAULT_CONNECTION_ALIAS);
        this.messages = Arrays.asList(messages);
        /*receiveMessageHelper = new ReceiveMessageHelper();
        sendMessageHelper = new SendMessageHelper();*/
    }

    public MessageAction(String connectionAlias) {
        super(connectionAlias);
        /*receiveMessageHelper = new ReceiveMessageHelper();
        sendMessageHelper = new SendMessageHelper();*/
    }

    public MessageAction(String connectionAlias, List<ProtocolMessage<?>> messages) {
        super(connectionAlias);
        this.messages = new ArrayList<>(messages);
        /*receiveMessageHelper = new ReceiveMessageHelper();
        sendMessageHelper = new SendMessageHelper();*/
    }

    public MessageAction(String connectionAlias, ProtocolMessage<?>... messages) {
        this(connectionAlias, Arrays.asList(messages));
    }

    public String getReadableString(ProtocolMessage<?>... messages) {
        return getReadableString(Arrays.asList(messages));
    }

    public String getReadableString(List<ProtocolMessage<?>> messages) {
        return getReadableString(messages, false);
    }

    public String getReadableString(List<ProtocolMessage<?>> messages, Boolean verbose) {
        if (messages == null || messages.isEmpty()) {
            return "";
        }
        StringBuilder builder = new StringBuilder();
        for (ProtocolMessage<?> message : messages) {
            if (verbose) {
                builder.append(message.toString());
            } else {
                builder.append(message.toCompactString());
            }
            if (!message.isRequired()) {
                builder.append("*");
            }
            builder.append(", ");
        }
        return builder.deleteCharAt(builder.lastIndexOf(", ")).toString();
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

    private void stripEmptyLists() {
        if (messages == null || messages.isEmpty()) {
            messages = null;
        }
    }

    private void initEmptyLists() {
        if (messages == null) {
            messages = new ArrayList<>();
        }
    }

    protected void send(
            SshContext sshContext,
            List<ProtocolMessage<?>> protocolMessagesToSend,
            List<AbstractPacket> packetsToSend)
            throws IOException {
        LayerStack layerStack = sshContext.getLayerStack();

        LayerConfiguration ssh2Configuration =
                new SpecificSendLayerConfiguration<>(
                        ImplementedLayers.SSHv2, protocolMessagesToSend);
        LayerConfiguration ssh1Configuration =
                new SpecificSendLayerConfiguration<>(
                        ImplementedLayers.SSHv1, protocolMessagesToSend);
        LayerConfiguration transportConfiguration =
                new SpecificSendLayerConfiguration<>(
                        ImplementedLayers.TransportLayer, packetsToSend);

        List<LayerConfiguration> layerConfigurationList =
                sortLayerConfigurations(
                        layerStack, ssh2Configuration, ssh1Configuration, transportConfiguration);
        LayerStackProcessingResult processingResult = layerStack.sendData(layerConfigurationList);
        setContainers(processingResult);
    }

    private void setContainers(LayerStackProcessingResult processingResults) {
        if (processingResults.getResultForLayer(ImplementedLayers.SSHv2) != null) {
            messages =
                    new ArrayList<>(
                            processingResults
                                    .getResultForLayer(ImplementedLayers.SSHv2)
                                    .getUsedContainers());
        }

        if (processingResults.getResultForLayer(ImplementedLayers.SSHv1) != null) {
            messages =
                    new ArrayList<>(
                            processingResults
                                    .getResultForLayer(ImplementedLayers.SSHv1)
                                    .getUsedContainers());
        }

        if (processingResults.getResultForLayer(ImplementedLayers.TransportLayer) != null) {
            packets =
                    new ArrayList<>(
                            processingResults
                                    .getResultForLayer(ImplementedLayers.TransportLayer)
                                    .getUsedContainers());
        }
    }

    protected void receive(
            SshContext sshContext,
            List<ProtocolMessage<?>> protocolMessagesToReceive,
            List<AbstractPacket> packetsToRecieve) {
        LayerStack layerStack = sshContext.getLayerStack();

        List<LayerConfiguration> layerConfigurationList;
        if (protocolMessagesToReceive == null && packetsToRecieve == null) {
            layerConfigurationList = getGenericReceiveConfigurations(layerStack);
        } else {
            layerConfigurationList =
                    getSpecificReceiveConfigurations(
                            protocolMessagesToReceive, packetsToRecieve, layerStack);
        }

        getReceiveResult(layerStack, layerConfigurationList);
    }

    private List<LayerConfiguration> getGenericReceiveConfigurations(LayerStack layerStack) {
        List<LayerConfiguration> layerConfigurationList;
        LayerConfiguration messageSsh2Configuration =
                new GenericReceiveLayerConfiguration(ImplementedLayers.SSHv2);
        LayerConfiguration messageSsh1Configuration =
                new GenericReceiveLayerConfiguration(ImplementedLayers.SSHv1);
        LayerConfiguration recordConfiguration =
                new GenericReceiveLayerConfiguration(ImplementedLayers.TransportLayer);
        layerConfigurationList =
                sortLayerConfigurations(
                        layerStack,
                        messageSsh2Configuration,
                        messageSsh1Configuration,
                        recordConfiguration);
        return layerConfigurationList;
    }

    private List<LayerConfiguration> getSpecificReceiveConfigurations(
            List<ProtocolMessage<?>> protocolMessagesToReceive,
            List<AbstractPacket> packetsToRecieve,
            LayerStack layerStack) {
        List<LayerConfiguration> layerConfigurationList;

        LayerConfiguration messageSsh2Configuration =
                new SpecificReceiveLayerConfiguration<>(
                        ImplementedLayers.SSHv2, protocolMessagesToReceive);
        LayerConfiguration messageSsh1Configuration =
                new SpecificReceiveLayerConfiguration<>(
                        ImplementedLayers.SSHv1, protocolMessagesToReceive);
        LayerConfiguration recordConfiguration =
                new SpecificReceiveLayerConfiguration<>(
                        ImplementedLayers.TransportLayer, packetsToRecieve);
        if (packetsToRecieve == null || packetsToRecieve.isEmpty()) {
            // always allow (trailing) records when no records were set
            // a ReceiveAction actually intended to expect no records is pointless
            ((SpecificReceiveLayerConfiguration) recordConfiguration)
                    .setAllowTrailingContainers(true);
        }
        /*        LayerConfiguration httpConfiguration =
        new SpecificReceiveLayerConfiguration<>(
                ImplementedLayers.HTTP, httpMessagesToReceive);*/
        applyActionOptionFilters(messageSsh1Configuration);
        applyActionOptionFilters(messageSsh2Configuration);
        layerConfigurationList =
                sortLayerConfigurations(
                        layerStack,
                        messageSsh2Configuration,
                        messageSsh1Configuration,
                        recordConfiguration);

        return layerConfigurationList;
    }

    private void applyActionOptionFilters(LayerConfiguration messageConfiguration) {
        List<DataContainerFilter> containerFilters = new LinkedList<>();
        /*if (getActionOptions().contains(ActionOption.IGNORE_UNEXPECTED_APP_DATA)) {
            containerFilters.add(new GenericDataContainerFilter(ApplicationMessage.class));
        }
        if (getActionOptions().contains(ActionOption.IGNORE_UNEXPECTED_KEY_UPDATE_MESSAGES)) {
            containerFilters.add(new GenericDataContainerFilter(KeyUpdateMessage.class));
        }
        if (getActionOptions().contains(ActionOption.IGNORE_UNEXPECTED_NEW_SESSION_TICKETS)) {
            containerFilters.add(new GenericDataContainerFilter(NewSessionTicketMessage.class));
        }
        if (getActionOptions().contains(ActionOption.IGNORE_UNEXPECTED_WARNINGS)) {
            containerFilters.add(new WarningAlertFilter());
        }*/
        ((SpecificReceiveLayerConfiguration) messageConfiguration)
                .setContainerFilterList(containerFilters);
    }

    private void getReceiveResult(
            LayerStack layerStack, List<LayerConfiguration> layerConfigurationList) {
        LayerStackProcessingResult processingResult;
        processingResult = layerStack.receiveData(layerConfigurationList);
        setContainers(processingResult);
        setLayerStackProcessingResult(processingResult);
    }

    public void setLayerStackProcessingResult(
            LayerStackProcessingResult layerStackProcessingResult) {
        this.layerStackProcessingResult = layerStackProcessingResult;
    }
}
