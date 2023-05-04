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
import de.rub.nds.sshattacker.core.protocol.common.*;
import de.rub.nds.sshattacker.core.state.SshContext;
import de.rub.nds.sshattacker.core.workflow.chooser.Chooser;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class UserAuthSuccessMessageHandler extends SshMessageHandler<UserAuthSuccessMessage>
        implements MessageSentHandler {

    private static final Logger LOGGER = LogManager.getLogger();

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
        // use negotiated compression method of delay-compression extension from SSH_MSG_EXT_INFO
        if (context.isHandleAsClient() && context.getConfig().getEnableExtensions()) {
            context.getPacketLayer()
                    .updateCompressionAlgorithm(
                            chooser.getSelectedDelayCompressionMethod().getAlgorithm());

            context.getPacketLayer()
                    .updateDecompressionAlgorithm(
                            chooser.getSelectedDelayCompressionMethod().getAlgorithm());
        }
        // only server can send SSH_MSG_USERAUTH_SUCCESS --> do nothing when receiving a
        // SSH_MSG_USERAUTH_SUCCESS from client
        else if (!context.isHandleAsClient()) {
            LOGGER.warn(
                    "Client sent UserAuthSuccessMessage which is supposed to be sent by server only !");
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

    @Override
    public UserAuthSuccessMessagePreparator getPreparator() {
        return new UserAuthSuccessMessagePreparator(context.getChooser(), message);
    }

    @Override
    public UserAuthSuccessMessageSerializer getSerializer() {
        return new UserAuthSuccessMessageSerializer(message);
    }
}
