/**
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * <p>Copyright 2014-2021 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * <p>Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.transport.handler;

import de.rub.nds.sshattacker.core.exceptions.AdjustmentException;
import de.rub.nds.sshattacker.core.protocol.common.*;
import de.rub.nds.sshattacker.core.protocol.transport.message.NewKeysMessage;
import de.rub.nds.sshattacker.core.protocol.transport.parser.NewKeysMessageParser;
import de.rub.nds.sshattacker.core.protocol.transport.preparator.NewKeysMessagePreparator;
import de.rub.nds.sshattacker.core.protocol.transport.serializer.NewKeysMessageSerializer;
import de.rub.nds.sshattacker.core.state.SshContext;

public class NewKeysMessageHandler extends SshMessageHandler<NewKeysMessage> {

    public NewKeysMessageHandler(SshContext context) {
        super(context);
    }

    public NewKeysMessageHandler(SshContext context, NewKeysMessage message) {
        super(context, message);
    }

    @Override
    public void adjustContext() {
        try {
            if (context.getConfig().getEnableEncryptionOnNewKeysMessage()) {
                context.setServerToClientEncryptionActive(true);
            }
        } catch (IllegalArgumentException e) {
            raiseAdjustmentException(new AdjustmentException(e));
        }
    }

    @Override
    public NewKeysMessageParser getParser(byte[] array, int startPosition) {
        return new NewKeysMessageParser(array, startPosition);
    }

    @Override
    public NewKeysMessagePreparator getPreparator() {
        return new NewKeysMessagePreparator(context, message);
    }

    @Override
    public NewKeysMessageSerializer getSerializer() {
        return new NewKeysMessageSerializer(message);
    }
}
