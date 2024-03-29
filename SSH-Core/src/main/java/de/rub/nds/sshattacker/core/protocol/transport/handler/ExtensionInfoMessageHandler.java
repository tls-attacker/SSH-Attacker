/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.transport.handler;

import de.rub.nds.sshattacker.core.layer.context.SshContext;
import de.rub.nds.sshattacker.core.protocol.common.SshMessageHandler;
import de.rub.nds.sshattacker.core.protocol.transport.message.ExtensionInfoMessage;

public class ExtensionInfoMessageHandler extends SshMessageHandler<ExtensionInfoMessage> {

    public ExtensionInfoMessageHandler(SshContext context) {
        super(context);
    }

    @Override
    public void adjustContext(ExtensionInfoMessage message) {
        if (sshContext.isHandleAsClient()) {
            sshContext.setServerSupportedExtensions(message.getExtensions());
        } else {
            sshContext.setClientSupportedExtensions(message.getExtensions());
        }
        message.getExtensions()
                .forEach(
                        extension -> {
                            extension.getHandler(sshContext).adjustContext(extension);
                        });
    }
}
