/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.workflow.action;

import de.rub.nds.sshattacker.core.exceptions.WorkflowExecutionException;
import de.rub.nds.sshattacker.core.layer.LayerConfiguration;
import de.rub.nds.sshattacker.core.layer.LayerStack;
import de.rub.nds.sshattacker.core.layer.LayerStackProcessingResult;
import de.rub.nds.sshattacker.core.layer.SpecificSendLayerConfiguration;
import de.rub.nds.sshattacker.core.layer.constant.ImplementedLayers;
import de.rub.nds.sshattacker.core.layer.context.SshContext;
import de.rub.nds.sshattacker.core.protocol.authentication.message.UserAuthHostbasedMessage;
import de.rub.nds.sshattacker.core.protocol.authentication.message.UserAuthPubkeyMessage;
import de.rub.nds.sshattacker.core.protocol.authentication.preparator.UserAuthHostbasedMessagePreparator;
import de.rub.nds.sshattacker.core.protocol.authentication.preparator.UserAuthPubkeyMessagePreparator;
import de.rub.nds.sshattacker.core.protocol.common.ProtocolMessage;
import de.rub.nds.sshattacker.core.state.State;
import jakarta.xml.bind.annotation.XmlTransient;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class ProxyFilterMessagesAction extends ForwardMessagesAction {

    private static final Logger LOGGER = LogManager.getLogger();

    // because sendMessages will contain filteredMessages, when storing the workflow trace, so it
    // would just make reading the trace more complicated
    @XmlTransient protected List<ProtocolMessage<?>> filteredMessages;

    public ProxyFilterMessagesAction() {
        /*        this.receiveMessageHelper = new ReceiveMessageHelper();
        this.sendMessageHelper = new SendMessageHelper();*/
    }

    /*    public ProxyFilterMessagesAction(String receiveFromAlias, String forwardToAlias) {
        super(receiveFromAlias, forwardToAlias, new ReceiveMessageHelper());
    }*/

    /** Allow to pass a fake ReceiveMessageHelper helper for testing. */
    protected ProxyFilterMessagesAction(String receiveFromAlias, String forwardToAlias) {
        super(receiveFromAlias, forwardToAlias);
    }

    public ProxyFilterMessagesAction(
            String receiveFromAlias, String forwardToAlias, List<ProtocolMessage<?>> messages) {
        super(receiveFromAlias, forwardToAlias, messages);
    }

    public ProxyFilterMessagesAction(
            String receiveFromAlias, String forwardToAlias, ProtocolMessage<?>... messages) {
        super(receiveFromAlias, forwardToAlias, messages);
    }

    @Override
    public void execute(State state) throws WorkflowExecutionException {
        if (isExecuted()) {
            throw new WorkflowExecutionException("Action already executed!");
        }

        assertAliasesSetProperly();

        SshContext receiveFromCtx = state.getSshContext(receiveFromAlias);
        SshContext forwardToCtx = state.getSshContext(forwardToAlias);
        initLoggingSide(receiveFromCtx);

        receiveMessages(receiveFromCtx);
        // - affected - handleReceivedMessages(receiveFromCtx);
        filterMessages(receiveFromCtx, forwardToCtx);
        applyMessages(forwardToCtx);
        forwardMessages(forwardToCtx);
    }

    @Override
    protected void forwardMessages(SshContext forwardToCtx) {
        LOGGER.info(
                "Forwarding messages ("
                        + forwardToAlias
                        + "): "
                        + getReadableString(filteredMessages));

        try {
            LayerStack layerStack = forwardToCtx.getLayerStack();
            LayerConfiguration messageConfiguration =
                    new SpecificSendLayerConfiguration(ImplementedLayers.SSHV2, filteredMessages);
            LayerConfiguration packetConfiguration =
                    new SpecificSendLayerConfiguration(
                            ImplementedLayers.PACKET_LAYER, receivedPackets);

            List<LayerConfiguration> layerConfigurationList =
                    sortLayerConfigurations(layerStack, messageConfiguration, packetConfiguration);
            LayerStackProcessingResult processingResult =
                    layerStack.sendData(layerConfigurationList);

            sendMessages =
                    new ArrayList<>(
                            processingResult
                                    .getResultForLayer(ImplementedLayers.SSHV2)
                                    .getUsedContainers());
            sendPackets =
                    new ArrayList<>(
                            processingResult
                                    .getResultForLayer(ImplementedLayers.PACKET_LAYER)
                                    .getUsedContainers());

            executedAsPlanned = checkMessageListsEquals(sendMessages, filteredMessages);

            setExecuted(true);

        } catch (IOException e) {
            LOGGER.debug(e);
            throw new RuntimeException(e);
        }

        /*MessageActionResult result =
                sendMessageHelper.sendMessages(forwardToCtx, filteredMessages.stream());
        sendMessages = result.getMessageList();

        if (executedAsPlanned) {
            executedAsPlanned = checkMessageListsEquals(sendMessages, messages);
        }*/
        setExecuted(true);
    }

    public void filterMessages(SshContext receiveFromCtx, SshContext forwardToCtx) {
        filteredMessages = receivedMessages;
        for (int i = 0; i < filteredMessages.size(); i++) {
            if (filteredMessages.get(i).getClass() == UserAuthPubkeyMessage.class) {
                filteredMessages.set(i, filterUserAuthPubkeyMessage(forwardToCtx));
            }
            if (filteredMessages.get(i).getClass() == UserAuthHostbasedMessage.class) {
                filteredMessages.set(i, filterUserAuthHostbasedMessage(forwardToCtx));
            }
        }
    }

    public UserAuthPubkeyMessage filterUserAuthPubkeyMessage(SshContext forwardToCtx) {
        UserAuthPubkeyMessage newPubkeyMessage = new UserAuthPubkeyMessage();
        UserAuthPubkeyMessagePreparator forwardContextPreparator =
                new UserAuthPubkeyMessagePreparator(forwardToCtx.getChooser(), newPubkeyMessage);
        forwardContextPreparator.prepare();
        return newPubkeyMessage;
    }

    public UserAuthHostbasedMessage filterUserAuthHostbasedMessage(SshContext forwardToCtx) {
        UserAuthHostbasedMessage newHostbasedMessage = new UserAuthHostbasedMessage();
        UserAuthHostbasedMessagePreparator forwardContextPreparator =
                new UserAuthHostbasedMessagePreparator(
                        forwardToCtx.getChooser(), newHostbasedMessage);
        forwardContextPreparator.prepare();
        return newHostbasedMessage;
    }
}
