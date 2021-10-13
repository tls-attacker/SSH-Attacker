/**
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * <p>Copyright 2014-2021 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * <p>Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.transport.handler;

import de.rub.nds.sshattacker.core.exceptions.AdjustmentException;
import de.rub.nds.sshattacker.core.protocol.common.Handler;
import de.rub.nds.sshattacker.core.protocol.transport.message.NewKeysMessage;
import de.rub.nds.sshattacker.core.state.SshContext;

public class NewKeysMessageHandler extends Handler<NewKeysMessage> {

    public NewKeysMessageHandler(SshContext context) {
        super(context);
    }

    @Override
    public void adjustContext(NewKeysMessage message) {
        try {
            if (context.getConfig().getEnableEncryptionOnNewKeysMessage()) {
                context.setServerToClientEncryptionActive(true);
            }
        } catch (IllegalArgumentException e) {
            raiseAdjustmentException(new AdjustmentException(e));
        }
    }
}
