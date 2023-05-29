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
    }
}
