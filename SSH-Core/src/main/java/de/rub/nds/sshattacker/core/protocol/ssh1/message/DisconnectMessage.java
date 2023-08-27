/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.ssh1.message;

import de.rub.nds.modifiablevariable.ModifiableVariableFactory;
import de.rub.nds.modifiablevariable.string.ModifiableString;
import de.rub.nds.sshattacker.core.crypto.kex.HybridKeyExchange;
import de.rub.nds.sshattacker.core.layer.context.SshContext;
import de.rub.nds.sshattacker.core.protocol.common.SshMessage;
import de.rub.nds.sshattacker.core.protocol.common.SshMessageParser;
import de.rub.nds.sshattacker.core.protocol.common.SshMessagePreparator;
import de.rub.nds.sshattacker.core.protocol.common.SshMessageSerializer;
import de.rub.nds.sshattacker.core.protocol.ssh1.handler.DisconnectMessageHandler;
import de.rub.nds.sshattacker.core.protocol.ssh1.parser.DisconnectMessageParser;
import de.rub.nds.sshattacker.core.protocol.ssh1.preparator.DisconnectMessagePreparator;
import de.rub.nds.sshattacker.core.protocol.ssh1.serializer.DisconnectMessageSerializier;
import java.io.InputStream;

public class DisconnectMessage extends SshMessage<DisconnectMessage> {

    private ModifiableString disconnectReason;

    public ModifiableString getDisconnectReason() {
        return disconnectReason;
    }

    public void setDisconnectReason(ModifiableString disconnectReason) {
        this.disconnectReason = disconnectReason;
    }

    public void setDisconnectReason(String disconnectReason) {
        this.disconnectReason =
                ModifiableVariableFactory.safelySetValue(this.disconnectReason, disconnectReason);
    }

    @Override
    public DisconnectMessageHandler getHandler(SshContext context) {
        return new DisconnectMessageHandler(context);
    }

    @Override
    public SshMessageParser<DisconnectMessage> getParser(SshContext context, InputStream stream) {
        HybridKeyExchange kex = context.getChooser().getHybridKeyExchange();
        return new DisconnectMessageParser(context, stream);
    }

    @Override
    public SshMessagePreparator<DisconnectMessage> getPreparator(SshContext context) {
        HybridKeyExchange kex = context.getChooser().getHybridKeyExchange();
        return new DisconnectMessagePreparator(context.getChooser(), this, kex.getCombiner());
    }

    @Override
    public SshMessageSerializer<DisconnectMessage> getSerializer(SshContext context) {
        HybridKeyExchange kex = context.getChooser().getHybridKeyExchange();
        return new DisconnectMessageSerializier(this, kex.getCombiner());
    }

    @Override
    public String toShortString() {
        return "CMSG_SESSION_KEY";
    }
}
