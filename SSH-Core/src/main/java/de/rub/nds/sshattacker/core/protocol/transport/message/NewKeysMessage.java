/**
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * <p>Copyright 2014-2021 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * <p>Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.transport.message;

import de.rub.nds.sshattacker.core.constants.MessageIDConstant;
import de.rub.nds.sshattacker.core.protocol.common.Message;
import de.rub.nds.sshattacker.core.protocol.transport.handler.NewKeysMessageHandler;
import de.rub.nds.sshattacker.core.protocol.transport.preparator.NewKeysMessagePreparator;
import de.rub.nds.sshattacker.core.protocol.transport.serializer.NewKeysMessageSerializer;
import de.rub.nds.sshattacker.core.state.SshContext;

public class NewKeysMessage extends Message<NewKeysMessage> {

    public NewKeysMessage() {
        super(MessageIDConstant.SSH_MSG_NEWKEYS);
    }

    @Override
    public NewKeysMessageHandler getHandler(SshContext context) {
        return new NewKeysMessageHandler(context);
    }

    @Override
    public NewKeysMessageSerializer getSerializer() {
        return new NewKeysMessageSerializer(this);
    }

    @Override
    public NewKeysMessagePreparator getPreparator(SshContext context) {
        return new NewKeysMessagePreparator(context, this);
    }
}
