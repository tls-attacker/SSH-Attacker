/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2025 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.connection.message;

import de.rub.nds.modifiablevariable.ModifiableVariableFactory;
import de.rub.nds.modifiablevariable.bytearray.ModifiableByteArray;
import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.sshattacker.core.crypto.keys.SshPublicKey;
import de.rub.nds.sshattacker.core.crypto.util.PublicKeyHelper;
import de.rub.nds.sshattacker.core.protocol.connection.handler.GlobalRequestHostKeysProveOpenSshMessageHandler;
import de.rub.nds.sshattacker.core.state.SshContext;
import de.rub.nds.sshattacker.core.util.Converter;
import de.rub.nds.sshattacker.core.workflow.chooser.Chooser;
import java.util.List;

public class GlobalRequestHostKeysProveOpenSshMessage
        extends GlobalRequestMessage<GlobalRequestHostKeysProveOpenSshMessage> {

    private ModifiableByteArray hostKeys;

    public GlobalRequestHostKeysProveOpenSshMessage() {
        super();
    }

    public GlobalRequestHostKeysProveOpenSshMessage(
            GlobalRequestHostKeysProveOpenSshMessage other) {
        super(other);
        hostKeys = other.hostKeys != null ? other.hostKeys.createCopy() : null;
    }

    @Override
    public GlobalRequestHostKeysProveOpenSshMessage createCopy() {
        return new GlobalRequestHostKeysProveOpenSshMessage(this);
    }

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

    public static final GlobalRequestHostKeysProveOpenSshMessageHandler HANDLER =
            new GlobalRequestHostKeysProveOpenSshMessageHandler();

    @Override
    public GlobalRequestHostKeysProveOpenSshMessageHandler getHandler() {
        return HANDLER;
    }

    @Override
    public void adjustContext(SshContext context) {
        HANDLER.adjustContext(context, this);
    }

    @Override
    public void prepare(Chooser chooser) {
        GlobalRequestHostKeysProveOpenSshMessageHandler.PREPARATOR.prepare(this, chooser);
    }

    @Override
    public byte[] serialize() {
        return GlobalRequestHostKeysProveOpenSshMessageHandler.SERIALIZER.serialize(this);
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
}
