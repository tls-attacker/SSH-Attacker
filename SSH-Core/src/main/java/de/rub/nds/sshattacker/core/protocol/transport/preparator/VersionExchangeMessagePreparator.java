/**
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * <p>Copyright 2014-2021 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * <p>Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.transport.preparator;

import de.rub.nds.sshattacker.core.protocol.common.Preparator;
import de.rub.nds.sshattacker.core.protocol.transport.message.VersionExchangeMessage;
import de.rub.nds.sshattacker.core.state.SshContext;

public class VersionExchangeMessagePreparator extends Preparator<VersionExchangeMessage> {

    public VersionExchangeMessagePreparator(SshContext context, VersionExchangeMessage message) {
        super(context, message);
    }

    @Override
    public void prepare() {
        if (context.isClient()) {
            getObject().setVersion(context.getChooser().getClientVersion());
            getObject().setComment(context.getChooser().getClientComment());
            context.getExchangeHashInstance().setClientVersion(getObject());
        } else {
            getObject().setVersion(context.getChooser().getServerVersion());
            getObject().setComment(context.getChooser().getServerComment());
            context.getExchangeHashInstance().setServerVersion(getObject());
        }
    }
}
