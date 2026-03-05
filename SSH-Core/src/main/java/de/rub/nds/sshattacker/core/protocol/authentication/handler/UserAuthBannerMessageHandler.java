/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2024 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.authentication.handler;

import de.rub.nds.sshattacker.core.protocol.authentication.message.UserAuthBannerMessage;
import de.rub.nds.sshattacker.core.protocol.common.GenericSshMessageParser;
import de.rub.nds.sshattacker.core.protocol.common.SshMessageHandler;
import de.rub.nds.sshattacker.core.state.SshContext;

public class UserAuthBannerMessageHandler extends SshMessageHandler<UserAuthBannerMessage> {

    @Override
    public void adjustContext(SshContext context, UserAuthBannerMessage object) {
        object.adjustContext(context);
    }

    @Override
    public GenericSshMessageParser<UserAuthBannerMessage> getParser(
            byte[] array, SshContext context) {
        return new GenericSshMessageParser<>(array, UserAuthBannerMessage::new);
    }

    @Override
    public GenericSshMessageParser<UserAuthBannerMessage> getParser(
            byte[] array, int startPosition, SshContext context) {
        return new GenericSshMessageParser<>(array, startPosition, UserAuthBannerMessage::new);
    }
}
