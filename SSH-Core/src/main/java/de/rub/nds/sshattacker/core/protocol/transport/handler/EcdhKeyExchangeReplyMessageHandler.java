/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.transport.handler;

import de.rub.nds.sshattacker.core.protocol.common.*;
import de.rub.nds.sshattacker.core.protocol.transport.message.EcdhKeyExchangeReplyMessage;
import de.rub.nds.sshattacker.core.protocol.transport.parser.EcdhKeyExchangeReplyMessageParser;
import de.rub.nds.sshattacker.core.protocol.transport.preparator.EcdhKeyExchangeReplyMessagePreparator;
import de.rub.nds.sshattacker.core.protocol.transport.serializer.EcdhKeyExchangeReplyMessageSerializer;
import de.rub.nds.sshattacker.core.protocol.util.KeyExchangeUtil;
import de.rub.nds.sshattacker.core.state.SshContext;

public class EcdhKeyExchangeReplyMessageHandler
        extends SshMessageHandler<EcdhKeyExchangeReplyMessage> {

    public EcdhKeyExchangeReplyMessageHandler(SshContext context) {
        super(context);
    }

    public EcdhKeyExchangeReplyMessageHandler(
            SshContext context, EcdhKeyExchangeReplyMessage message) {
        super(context, message);
    }

    @Override
    public void adjustContext() {

        KeyExchangeUtil.handleHostKeyMessage(context, message);
        updateContextWithRemotePublicKey();
        KeyExchangeUtil.computeSharedSecret(context, context.getChooser().getEcdhKeyExchange());
        KeyExchangeUtil.computeExchangeHash(context);
        KeyExchangeUtil.handleExchangeHashSignatureMessage(context, message);
        KeyExchangeUtil.setSessionId(context);
        KeyExchangeUtil.generateKeySet(context);

        // Invalid Curve Mod: We get a custom keypair and set them here. The private key is not
        // relevant, the public key is the invalid point we send to the server.
        // Config sshConfig = context.getChooser().getConfig();

        /*context.getChooser()
                .getEcdhKeyExchange()
               .setLocalKeyPair(
                        sshConfig.getCustomEcPrivateKey(), sshConfig.getCustomEcPublicKey());

        KeyExchangeUtil.computeSharedSecret(context, context.getChooser().getEcdhKeyExchange());*/
    }

    private void updateContextWithRemotePublicKey() {
        context.getChooser()
                .getEcdhKeyExchange()
                .setRemotePublicKey(message.getEphemeralPublicKey().getValue());
        context.getExchangeHashInputHolder()
                .setEcdhServerPublicKey(message.getEphemeralPublicKey().getValue());
    }

    @Override
    public EcdhKeyExchangeReplyMessageParser getParser(byte[] array) {
        return new EcdhKeyExchangeReplyMessageParser(array);
    }

    @Override
    public EcdhKeyExchangeReplyMessageParser getParser(byte[] array, int startPosition) {
        return new EcdhKeyExchangeReplyMessageParser(array, startPosition);
    }

    @Override
    public EcdhKeyExchangeReplyMessagePreparator getPreparator() {
        return new EcdhKeyExchangeReplyMessagePreparator(context.getChooser(), message);
    }

    @Override
    public EcdhKeyExchangeReplyMessageSerializer getSerializer() {
        return new EcdhKeyExchangeReplyMessageSerializer(message);
    }
}
