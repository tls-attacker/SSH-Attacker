/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.authentication.handler;

import de.rub.nds.sshattacker.core.protocol.authentication.message.UserAuthBannerMessage;
import de.rub.nds.sshattacker.core.protocol.authentication.parser.UserAuthBannerMessageParser;
import de.rub.nds.sshattacker.core.protocol.authentication.preparator.UserAuthBannerMessagePreparator;
import de.rub.nds.sshattacker.core.protocol.authentication.serializer.UserAuthBannerMessageSerializer;
import de.rub.nds.sshattacker.core.protocol.common.*;
import de.rub.nds.sshattacker.core.state.SshContext;

public class UserAuthBannerMessageHandler extends SshMessageHandler<UserAuthBannerMessage> {

    public UserAuthBannerMessageHandler(SshContext context) {
        super(context);
    }

    public UserAuthBannerMessageHandler(SshContext context, UserAuthBannerMessage message) {
        super(context, message);
    }

    @Override
    public void adjustContext() {
        // TODO: Handle UserAuthBannerMessage
    }

    @Override
    public UserAuthBannerMessageParser getParser(byte[] array, int startPosition) {
        return new UserAuthBannerMessageParser(array, startPosition);
    }

    @Override
    public UserAuthBannerMessagePreparator getPreparator() {
        return new UserAuthBannerMessagePreparator(context.getChooser(), message);
    }

    @Override
    public UserAuthBannerMessageSerializer getSerializer() {
        return new UserAuthBannerMessageSerializer(message);
    }
}
