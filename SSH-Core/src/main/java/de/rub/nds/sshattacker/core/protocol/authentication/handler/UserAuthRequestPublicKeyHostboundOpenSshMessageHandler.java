/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.authentication.handler;

import de.rub.nds.sshattacker.core.protocol.authentication.message.UserAuthRequestPublicKeyHostboundOpenSshMessage;
import de.rub.nds.sshattacker.core.protocol.authentication.parser.UserAuthRequestPublicKeyHostboundOpenSshMessageParser;
import de.rub.nds.sshattacker.core.protocol.authentication.preparator.UserAuthRequestPublicKeyHostboundOpenSshMessagePreparator;
import de.rub.nds.sshattacker.core.protocol.authentication.serializer.UserAuthRequestPublicKeyHostboundOpenSshMessageSerializer;
import de.rub.nds.sshattacker.core.protocol.common.SshMessageHandler;
import de.rub.nds.sshattacker.core.state.SshContext;

public class UserAuthRequestPublicKeyHostboundOpenSshMessageHandler
        extends SshMessageHandler<UserAuthRequestPublicKeyHostboundOpenSshMessage> {

    public UserAuthRequestPublicKeyHostboundOpenSshMessageHandler(SshContext context) {
        super(context);
    }

    public UserAuthRequestPublicKeyHostboundOpenSshMessageHandler(
            SshContext context, UserAuthRequestPublicKeyHostboundOpenSshMessage message) {
        super(context, message);
    }

    @Override
    public void adjustContext() {}

    @Override
    public UserAuthRequestPublicKeyHostboundOpenSshMessageParser getParser(byte[] array) {
        return new UserAuthRequestPublicKeyHostboundOpenSshMessageParser(array);
    }

    @Override
    public UserAuthRequestPublicKeyHostboundOpenSshMessageParser getParser(
            byte[] array, int startPosition) {
        return new UserAuthRequestPublicKeyHostboundOpenSshMessageParser(array, startPosition);
    }

    @Override
    public UserAuthRequestPublicKeyHostboundOpenSshMessagePreparator getPreparator() {
        return new UserAuthRequestPublicKeyHostboundOpenSshMessagePreparator(
                context.getChooser(), message);
    }

    @Override
    public UserAuthRequestPublicKeyHostboundOpenSshMessageSerializer getSerializer() {
        return new UserAuthRequestPublicKeyHostboundOpenSshMessageSerializer(message);
    }
}
