/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.authentication.handler;

import de.rub.nds.sshattacker.core.constants.CompressionMethod;
import de.rub.nds.sshattacker.core.layer.context.SshContext;
import de.rub.nds.sshattacker.core.protocol.authentication.message.UserAuthSuccessMessage;
import de.rub.nds.sshattacker.core.protocol.common.*;
import de.rub.nds.sshattacker.core.workflow.chooser.Chooser;

public class UserAuthSuccessMessageHandler extends SshMessageHandler<UserAuthSuccessMessage>
        implements MessageSentHandler {

    public UserAuthSuccessMessageHandler(SshContext context) {
        super(context);
    }

    /*public UserAuthSuccessMessageHandler(SshContext context, UserAuthSuccessMessage message) {
        super(context, message);
    }*/

    @Override
    public void adjustContext(UserAuthSuccessMessage message) {
        // Enable delayed compression if negotiated
        activateCompression();
    }

    @Override
    public void adjustContextAfterMessageSent() {
        // Enable delayed compression if negotiated
        activateCompression();
        if (!sshContext.isClient()
                && sshContext.delayCompressionExtensionReceived()
                && sshContext.getConfig().getRespectDelayCompressionExtension()
                && !sshContext.getDelayCompressionExtensionNegotiationFailed()
                && sshContext.getSelectedDelayCompressionMethod().isPresent()) {
            sshContext
                    .getPacketLayer()
                    .updateCompressionAlgorithm(
                            sshContext.getSelectedDelayCompressionMethod().get().getAlgorithm());
        }
    }

    private void activateCompression() {
        Chooser chooser = sshContext.getChooser();
        if (chooser.getCompressionMethodClientToServer() == CompressionMethod.ZLIB_OPENSSH_COM) {
            sshContext
                    .getPacketLayer()
                    .updateCompressionAlgorithm(
                            chooser.getCompressionMethodClientToServer().getAlgorithm());
        }
        if (chooser.getCompressionMethodServerToClient() == CompressionMethod.ZLIB_OPENSSH_COM) {
            sshContext
                    .getPacketLayer()
                    .updateDecompressionAlgorithm(
                            chooser.getCompressionMethodServerToClient().getAlgorithm());
        }
        // receiving UserAuthSuccessMessage when acting as client
        // --> set new compression algorithm from delay-compression extension
        if (sshContext.isHandleAsClient()
                && sshContext.getConfig().getRespectDelayCompressionExtension()
                && sshContext.delayCompressionExtensionReceived()
                && !sshContext.getDelayCompressionExtensionNegotiationFailed()
                && sshContext.getSelectedDelayCompressionMethod().isPresent()) {
            sshContext
                    .getPacketLayer()
                    .updateDecompressionAlgorithm(
                            sshContext.getSelectedDelayCompressionMethod().get().getAlgorithm());
        }
        // receiving UserAuthSuccessMessage when acting as server
        else {
            LOGGER.debug(
                    "Client sent UserAuthSuccessMessage which is supposed to be sent by the server only!");
        }
    }
}
