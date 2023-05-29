/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.transport.message;

import de.rub.nds.modifiablevariable.ModifiableVariableFactory;
import de.rub.nds.modifiablevariable.integer.ModifiableInteger;
import de.rub.nds.sshattacker.core.layer.context.SshContext;
import de.rub.nds.sshattacker.core.protocol.common.*;
import de.rub.nds.sshattacker.core.protocol.transport.handler.DhGexKeyExchangeOldRequestMessageHandler;
import de.rub.nds.sshattacker.core.protocol.transport.parser.DhGexKeyExchangeOldRequestMessageParser;
import de.rub.nds.sshattacker.core.protocol.transport.preparator.DhGexKeyExchangeOldRequestMessagePreparator;
import de.rub.nds.sshattacker.core.protocol.transport.serializer.DhGexKeyExchangeOldRequestMessageSerializer;
import java.io.InputStream;

public class DhGexKeyExchangeOldRequestMessage
        extends SshMessage<DhGexKeyExchangeOldRequestMessage> {

    private ModifiableInteger preferredGroupSize;

    public ModifiableInteger getPreferredGroupSize() {
        return preferredGroupSize;
    }

    public void setPreferredGroupSize(ModifiableInteger preferredGroupSize) {
        this.preferredGroupSize = preferredGroupSize;
    }

    public void setPreferredGroupSize(int preferredGroupSize) {
        this.preferredGroupSize =
                ModifiableVariableFactory.safelySetValue(
                        this.preferredGroupSize, preferredGroupSize);
    }

    @Override
    public DhGexKeyExchangeOldRequestMessageHandler getHandler(SshContext context) {
        return new DhGexKeyExchangeOldRequestMessageHandler(context);
    }

    @Override
    public SshMessageParser<DhGexKeyExchangeOldRequestMessage> getParser(
            SshContext context, InputStream stream) {
        return new DhGexKeyExchangeOldRequestMessageParser(stream);
    }

    @Override
    public DhGexKeyExchangeOldRequestMessagePreparator getPreparator(SshContext context) {
        return new DhGexKeyExchangeOldRequestMessagePreparator(context.getChooser(), this);
    }

    @Override
    public DhGexKeyExchangeOldRequestMessageSerializer getSerializer(SshContext context) {
        return new DhGexKeyExchangeOldRequestMessageSerializer(this);
    }

    @Override
    public String toShortString() {
        return "DHGKexOldRequest";
    }
}
