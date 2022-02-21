/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.crypto.hash;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.sshattacker.core.state.SshContext;
import de.rub.nds.sshattacker.core.util.Converter;
import java.security.PublicKey;

public class EcdhExchangeHash extends ExchangeHash {

    private byte[] serverECDHPublicKey;
    private byte[] clientECDHPublicKey;

    public EcdhExchangeHash(SshContext context) {
        super(context);
    }

    public byte[] getClientECDHPublicKey() {
        return clientECDHPublicKey;
    }

    public void setClientECDHPublicKey(byte[] clientECDHPublicKey) {
        this.clientECDHPublicKey = clientECDHPublicKey;
    }

    public void setClientECDHPublicKey(PublicKey clientECDHPublicKey) {
        this.clientECDHPublicKey = clientECDHPublicKey.getEncoded();
    }

    public byte[] getServerECDHPublicKey() {
        return serverECDHPublicKey;
    }

    public void setServerECDHPublicKey(byte[] serverECDHPublicKey) {
        this.serverECDHPublicKey = serverECDHPublicKey;
    }

    public void setServerECDHPublicKey(PublicKey serverECDHPublicKey) {
        this.serverECDHPublicKey = serverECDHPublicKey.getEncoded();
    }

    @Override
    protected boolean areRequiredInputsMissing() {
        return super.areRequiredInputsMissing()
                || serverECDHPublicKey == null
                || clientECDHPublicKey == null;
    }

    @Override
    protected byte[] getHashInput() {
        return ArrayConverter.concatenate(
                Converter.stringToLengthPrefixedBinaryString(clientVersion),
                Converter.stringToLengthPrefixedBinaryString(serverVersion),
                Converter.bytesToLengthPrefixedBinaryString(clientKeyExchangeInit),
                Converter.bytesToLengthPrefixedBinaryString(serverKeyExchangeInit),
                Converter.bytesToLengthPrefixedBinaryString(serverHostKey),
                Converter.bytesToLengthPrefixedBinaryString(clientECDHPublicKey),
                Converter.bytesToLengthPrefixedBinaryString(serverECDHPublicKey),
                Converter.byteArrayToMpint(sharedSecret));
    }

    public static EcdhExchangeHash from(ExchangeHash exchangeHash) {
        EcdhExchangeHash ecdhExchangeHash = new EcdhExchangeHash(exchangeHash.context);
        ecdhExchangeHash.setClientVersion(exchangeHash.clientVersion);
        ecdhExchangeHash.setServerVersion(exchangeHash.serverVersion);
        ecdhExchangeHash.setClientKeyExchangeInit(exchangeHash.clientKeyExchangeInit);
        ecdhExchangeHash.setServerKeyExchangeInit(exchangeHash.serverKeyExchangeInit);
        ecdhExchangeHash.setServerHostKey(exchangeHash.serverHostKey);
        ecdhExchangeHash.setSharedSecret(exchangeHash.sharedSecret);
        if (exchangeHash instanceof EcdhExchangeHash) {
            ecdhExchangeHash.setClientECDHPublicKey(
                    ((EcdhExchangeHash) exchangeHash).clientECDHPublicKey);
            ecdhExchangeHash.setServerECDHPublicKey(
                    ((EcdhExchangeHash) exchangeHash).serverECDHPublicKey);
        }
        return ecdhExchangeHash;
    }
}
