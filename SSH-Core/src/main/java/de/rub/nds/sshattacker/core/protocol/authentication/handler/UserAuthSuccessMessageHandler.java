/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.authentication.handler;

import de.rub.nds.sshattacker.core.constants.CompressionMethod;
import de.rub.nds.sshattacker.core.protocol.authentication.message.UserAuthSuccessMessage;
import de.rub.nds.sshattacker.core.protocol.authentication.parser.UserAuthSuccessMessageParser;
import de.rub.nds.sshattacker.core.protocol.authentication.preparator.UserAuthSuccessMessagePreparator;
import de.rub.nds.sshattacker.core.protocol.authentication.serializer.UserAuthSuccessMessageSerializer;
import de.rub.nds.sshattacker.core.protocol.common.MessageSentHandler;
import de.rub.nds.sshattacker.core.protocol.common.SshMessageHandler;
import de.rub.nds.sshattacker.core.state.SshContext;
import de.rub.nds.sshattacker.core.workflow.chooser.Chooser;

public class UserAuthSuccessMessageHandler extends SshMessageHandler<UserAuthSuccessMessage>
        implements MessageSentHandler {

    public UserAuthSuccessMessageHandler(SshContext context) {
        super(context);
    }

    public UserAuthSuccessMessageHandler(SshContext context, UserAuthSuccessMessage message) {
        super(context, message);
    }

    @Override
    public void adjustContext() {
        // Enable delayed compression if negotiated
        activateCompression();
    }

    @Override
    public void adjustContextAfterMessageSent() {
        // Enable delayed compression if negotiated
        activateCompression();
        if (!context.isClient()
                && context.delayCompressionExtensionReceived()
                && context.getConfig().getRespectDelayCompressionExtension()
                && !context.getDelayCompressionExtensionNegotiationFailed()
                && context.getSelectedDelayCompressionMethod().isPresent()) {
            context.getPacketLayer()
                    .updateCompressionAlgorithm(
                            context.getSelectedDelayCompressionMethod().get().getAlgorithm());
        }
    }

    private void activateCompression() {
        Chooser chooser = context.getChooser();
        if (chooser.getCompressionMethodClientToServer() == CompressionMethod.ZLIB_OPENSSH_COM) {
            context.getPacketLayer()
                    .updateCompressionAlgorithm(
                            chooser.getCompressionMethodClientToServer().getAlgorithm());
        }
        if (chooser.getCompressionMethodServerToClient() == CompressionMethod.ZLIB_OPENSSH_COM) {
            context.getPacketLayer()
                    .updateDecompressionAlgorithm(
                            chooser.getCompressionMethodServerToClient().getAlgorithm());
        }
        // receiving UserAuthSuccessMessage when acting as client
        // --> set new compression algorithm from delay-compression extension
        if (context.isHandleAsClient()
                && context.getConfig().getRespectDelayCompressionExtension()
                && context.delayCompressionExtensionReceived()
                && !context.getDelayCompressionExtensionNegotiationFailed()
                && context.getSelectedDelayCompressionMethod().isPresent()) {
            context.getPacketLayer()
                    .updateDecompressionAlgorithm(
                            context.getSelectedDelayCompressionMethod().get().getAlgorithm());
        }
        // receiving UserAuthSuccessMessage when acting as server
        else {
            LOGGER.debug(
                    "Client sent UserAuthSuccessMessage which is supposed to be sent by the server only!");
        }
    }

    @Override
    public UserAuthSuccessMessageParser getParser(byte[] array) {
        return new UserAuthSuccessMessageParser(array);
    }

    @Override
    public UserAuthSuccessMessageParser getParser(byte[] array, int startPosition) {
        return new UserAuthSuccessMessageParser(array, startPosition);
    }

    public static final UserAuthSuccessMessagePreparator PREPARATOR =
            new UserAuthSuccessMessagePreparator();

    public static final UserAuthSuccessMessageSerializer SERIALIZER =
            new UserAuthSuccessMessageSerializer();
}
