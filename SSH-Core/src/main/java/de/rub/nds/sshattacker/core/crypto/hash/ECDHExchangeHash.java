/**
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2021 Ruhr University Bochum, Paderborn University,
 * and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.crypto.hash;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.sshattacker.core.crypto.keys.CustomECPublicKey;
import de.rub.nds.sshattacker.core.state.SshContext;
import de.rub.nds.sshattacker.core.util.Converter;

public class ECDHExchangeHash extends ExchangeHash {

    private byte[] serverECDHPublicKey;
    private byte[] clientECDHPublicKey;

    public ECDHExchangeHash(SshContext context) {
        super(context);
    }

    public byte[] getClientECDHPublicKey() {
        return clientECDHPublicKey;
    }

    public void setClientECDHPublicKey(byte[] clientECDHPublicKey) {
        this.clientECDHPublicKey = clientECDHPublicKey;
    }

    public void setClientECDHPublicKey(CustomECPublicKey clientECDHPublicKey) {
        this.clientECDHPublicKey = clientECDHPublicKey.getEncoded();
    }

    public byte[] getServerECDHPublicKey() {
        return serverECDHPublicKey;
    }

    public void setServerECDHPublicKey(byte[] serverECDHPublicKey) {
        this.serverECDHPublicKey = serverECDHPublicKey;
    }

    public void setServerECDHPublicKey(CustomECPublicKey serverECDHPublicKey) {
        this.serverECDHPublicKey = serverECDHPublicKey.getEncoded();
    }

    @Override
    protected boolean areRequiredInputsMissing() {
        return super.areRequiredInputsMissing() || serverECDHPublicKey == null || clientECDHPublicKey == null;
    }

    @Override
    protected byte[] getHashInput() {
        return ArrayConverter.concatenate(Converter.stringToLengthPrefixedBinaryString(clientVersion),
                Converter.stringToLengthPrefixedBinaryString(serverVersion),
                Converter.bytesToLengthPrefixedBinaryString(clientKeyExchangeInit),
                Converter.bytesToLengthPrefixedBinaryString(serverKeyExchangeInit),
                Converter.bytesToLengthPrefixedBinaryString(serverHostKey),
                Converter.bytesToLengthPrefixedBinaryString(clientECDHPublicKey),
                Converter.bytesToLengthPrefixedBinaryString(serverECDHPublicKey),
                Converter.byteArrayToMpint(sharedSecret));
    }

    public static ECDHExchangeHash from(ExchangeHash exchangeHash) {
        ECDHExchangeHash ecdhExchangeHash = new ECDHExchangeHash(exchangeHash.context);
        ecdhExchangeHash.setClientVersion(exchangeHash.clientVersion);
        ecdhExchangeHash.setServerVersion(exchangeHash.serverVersion);
        ecdhExchangeHash.setClientKeyExchangeInit(exchangeHash.clientKeyExchangeInit);
        ecdhExchangeHash.setServerKeyExchangeInit(exchangeHash.serverKeyExchangeInit);
        ecdhExchangeHash.setServerHostKey(exchangeHash.serverHostKey);
        ecdhExchangeHash.setSharedSecret(exchangeHash.sharedSecret);
        if (exchangeHash instanceof ECDHExchangeHash) {
            ecdhExchangeHash.setClientECDHPublicKey(((ECDHExchangeHash) exchangeHash).clientECDHPublicKey);
            ecdhExchangeHash.setServerECDHPublicKey(((ECDHExchangeHash) exchangeHash).serverECDHPublicKey);
        }
        return ecdhExchangeHash;
    }
}
