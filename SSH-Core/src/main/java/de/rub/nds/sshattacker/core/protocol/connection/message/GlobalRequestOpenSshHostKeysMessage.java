/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.connection.message;

import de.rub.nds.modifiablevariable.ModifiableVariableFactory;
import de.rub.nds.modifiablevariable.bytearray.ModifiableByteArray;
import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.sshattacker.core.crypto.keys.SshPublicKey;
import de.rub.nds.sshattacker.core.crypto.util.PublicKeyHelper;
import de.rub.nds.sshattacker.core.layer.context.SshContext;
import de.rub.nds.sshattacker.core.protocol.common.SshMessageParser;
import de.rub.nds.sshattacker.core.protocol.common.SshMessagePreparator;
import de.rub.nds.sshattacker.core.protocol.common.SshMessageSerializer;
import de.rub.nds.sshattacker.core.protocol.connection.handler.GlobalRequestOpenSshHostKeysMessageHandler;
import de.rub.nds.sshattacker.core.protocol.connection.parser.GlobalRequestOpenSshHostKeysMessageParser;
import de.rub.nds.sshattacker.core.protocol.connection.preparator.GlobalRequestOpenSshHostKeysMessagePreparator;
import de.rub.nds.sshattacker.core.protocol.connection.serializer.GlobalRequestOpenSshHostKeysMessageSerializer;
import de.rub.nds.sshattacker.core.util.Converter;
import java.io.InputStream;
import java.util.List;

public class GlobalRequestOpenSshHostKeysMessage
        extends GlobalRequestMessage<GlobalRequestOpenSshHostKeysMessage> {

    private ModifiableByteArray hostKeys;

    public ModifiableByteArray getHostKeys() {
        return hostKeys;
    }

    public void setHostKeys(ModifiableByteArray hostKeys) {
        this.hostKeys = hostKeys;
    }

    public void setHostKeys(byte[] hostKeys) {
        this.hostKeys = ModifiableVariableFactory.safelySetValue(this.hostKeys, hostKeys);
    }

    public void setHostKeys(List<SshPublicKey<?, ?>> hostKeys) {
        this.hostKeys =
                ModifiableVariableFactory.safelySetValue(this.hostKeys, encodeKeys(hostKeys));
    }

    @Override
    public GlobalRequestOpenSshHostKeysMessageHandler getHandler(SshContext context) {
        return new GlobalRequestOpenSshHostKeysMessageHandler(context);
    }

    @Override
    public SshMessageParser<GlobalRequestOpenSshHostKeysMessage> getParser(
            SshContext context, InputStream stream) {
        return new GlobalRequestOpenSshHostKeysMessageParser(stream);
    }

    @Override
    public SshMessagePreparator<GlobalRequestOpenSshHostKeysMessage> getPreparator(
            SshContext context) {
        return new GlobalRequestOpenSshHostKeysMessagePreparator(context.getChooser(), this);
    }

    @Override
    public SshMessageSerializer<GlobalRequestOpenSshHostKeysMessage> getSerializer(
            SshContext context) {
        return new GlobalRequestOpenSshHostKeysMessageSerializer(this);
    }

    /**
     * Encodes a list of keys into a host key blob value, consisting of one length-prefixed string
     * per key.
     *
     * @param keys the list of keys to encode
     * @return the encoded key blob
     */
    private static byte[] encodeKeys(List<SshPublicKey<?, ?>> keys) {
        return keys.stream()
                .map(PublicKeyHelper::encode)
                .map(Converter::bytesToLengthPrefixedBinaryString)
                .reduce(ArrayConverter::concatenate)
                .orElseGet(() -> new byte[0]);
    }

    @Override
    public String toShortString() {
        return "OPENSSH";
    }
}
