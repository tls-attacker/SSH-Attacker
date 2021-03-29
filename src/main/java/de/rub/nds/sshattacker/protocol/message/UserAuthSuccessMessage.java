/**
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2021 Ruhr University Bochum, Paderborn University,
 * and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.protocol.message;

import de.rub.nds.sshattacker.protocol.handler.UserAuthSuccessMessageHandler;
import de.rub.nds.sshattacker.protocol.preparator.UserAuthSuccessMessagePreparator;
import de.rub.nds.sshattacker.protocol.serializer.UserAuthSuccessMessageSerializer;
import de.rub.nds.sshattacker.state.SshContext;

public class UserAuthSuccessMessage extends Message<UserAuthSuccessMessage> {

    @Override
    public UserAuthSuccessMessageHandler getHandler(SshContext context) {
        return new UserAuthSuccessMessageHandler(context);
    }

    @Override
    public UserAuthSuccessMessageSerializer getSerializer() {
        return new UserAuthSuccessMessageSerializer(this);
    }

    @Override
    public UserAuthSuccessMessagePreparator getPreparator(SshContext context) {
        return new UserAuthSuccessMessagePreparator(context, this);
    }

}
