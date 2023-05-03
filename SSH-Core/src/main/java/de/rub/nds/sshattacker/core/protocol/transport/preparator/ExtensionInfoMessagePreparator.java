/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.transport.preparator;

import de.rub.nds.sshattacker.core.constants.*;
import de.rub.nds.sshattacker.core.protocol.common.SshMessagePreparator;
import de.rub.nds.sshattacker.core.protocol.transport.message.ExtensionInfoMessage;
import de.rub.nds.sshattacker.core.workflow.chooser.Chooser;

public class ExtensionInfoMessagePreparator extends SshMessagePreparator<ExtensionInfoMessage> {

    public ExtensionInfoMessagePreparator(Chooser chooser, ExtensionInfoMessage message) {
        super(chooser, message, MessageIdConstant.SSH_MSG_EXT_INFO);
    }

    @Override
    public void prepareMessageSpecificContents() {
        // send delay-compression extension by default when acting as client
        if (chooser.getContext().isClient()) {
            // setting default extensions in constructor of config class throws a
            // java.io.NotSerializableException
            // (the reason why it is done this way:)
            chooser.getConfig().setDefaultExtensionsForClient();
            getObject().setExtensionCount(chooser.getClientSupportedExtensions().size());
            getObject().setExtensions(chooser.getClientSupportedExtensions());
        }
        // send server-sig-algs and delay-compression extension by default when acting as server
        else {
            chooser.getConfig().setDefaultExtensionsForServer();
            getObject().setExtensionCount(chooser.getServerSupportedExtensions().size());
            getObject().setExtensions(chooser.getServerSupportedExtensions());
        }

        getObject()
                .getExtensions()
                .forEach(
                        extension ->
                                extension
                                        .getHandler(chooser.getContext())
                                        .getPreparator()
                                        .prepare());
    }
}
