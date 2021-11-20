/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2021 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.workflow.action.executor;

import de.rub.nds.sshattacker.core.constants.EncryptionAlgorithm;
import de.rub.nds.sshattacker.core.constants.MacAlgorithm;
import de.rub.nds.sshattacker.core.packet.cipher.PacketCipherFactory;
import de.rub.nds.sshattacker.core.packet.cipher.keys.KeySet;
import de.rub.nds.sshattacker.core.packet.cipher.keys.KeySetGenerator;
import de.rub.nds.sshattacker.core.exceptions.WorkflowExecutionException;
import de.rub.nds.sshattacker.core.protocol.common.ProtocolMessage;
import de.rub.nds.sshattacker.core.protocol.common.layer.MessageLayer;
import de.rub.nds.sshattacker.core.packet.AbstractPacket;
import de.rub.nds.sshattacker.core.packet.layer.AbstractPacketLayer;
import de.rub.nds.sshattacker.core.protocol.transport.message.NewKeysMessage;
import de.rub.nds.sshattacker.core.state.SshContext;
import de.rub.nds.tlsattacker.transport.TransportHandler;
import java.io.IOException;
import java.util.Collections;
import java.util.stream.Stream;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class SendMessageHelper {

    private static final Logger LOGGER = LogManager.getLogger();

    public void sendPacket(SshContext context, AbstractPacket packet) throws IOException {
        AbstractPacketLayer packetLayer = context.getPacketLayer();
        TransportHandler transportHandler = context.getTransportHandler();
        transportHandler.sendData(packetLayer.preparePacket(packet));
    }

    public MessageActionResult sendMessage(SshContext context, ProtocolMessage<?> message) {
        MessageLayer messageLayer = context.getMessageLayer();
        try {
            AbstractPacket packet = messageLayer.serialize(message);
            sendPacket(context, packet);
            try {
                if (message instanceof NewKeysMessage
                        && context.getConfig().getEnableEncryptionOnNewKeysMessage()) {
                    KeySet keySet = KeySetGenerator.generateKeySet(context);
                    EncryptionAlgorithm outEnc =
                            context.isClient()
                                    ? context.getCipherAlgorithmClientToServer()
                                            .orElseThrow(WorkflowExecutionException::new)
                                    : context.getCipherAlgorithmServerToClient()
                                            .orElseThrow(WorkflowExecutionException::new);
                    MacAlgorithm outMac =
                            context.isClient()
                                    ? context.getMacAlgorithmClientToServer()
                                            .orElseThrow(WorkflowExecutionException::new)
                                    : context.getMacAlgorithmServerToClient()
                                            .orElseThrow(WorkflowExecutionException::new);
                    context.getPacketLayer()
                            .updateEncryptionCipher(
                                    PacketCipherFactory.getPacketCipher(
                                            context, keySet, outEnc, outMac));
                }
            } catch (IllegalArgumentException ignored) {
            }
            return new MessageActionResult(
                    Collections.singletonList(packet), Collections.singletonList(message));
        } catch (IOException e) {
            LOGGER.warn("Error while sending packet: " + e.getMessage());
            return new MessageActionResult();
        }
    }

    public MessageActionResult sendMessages(
            SshContext context, Stream<ProtocolMessage<?>> messageStream) {
        return messageStream
                .map(message -> sendMessage(context, message))
                .reduce(MessageActionResult::merge)
                .orElse(new MessageActionResult());
    }
}
