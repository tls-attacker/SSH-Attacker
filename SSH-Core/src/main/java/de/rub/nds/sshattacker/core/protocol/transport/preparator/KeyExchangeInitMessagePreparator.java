/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2021 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.transport.preparator;

import de.rub.nds.sshattacker.core.constants.MessageIDConstant;
import de.rub.nds.sshattacker.core.protocol.common.SshMessagePreparator;
import de.rub.nds.sshattacker.core.protocol.transport.message.KeyExchangeInitMessage;
import de.rub.nds.sshattacker.core.state.SshContext;

public class KeyExchangeInitMessagePreparator extends SshMessagePreparator<KeyExchangeInitMessage> {

    public KeyExchangeInitMessagePreparator(SshContext context, KeyExchangeInitMessage message) {
        super(context, message);
    }

    @Override
    public void prepareMessageSpecificContents() {
        getObject().setMessageID(MessageIDConstant.SSH_MSG_KEXINIT);
        if (context.isClient()) {
            getObject().setCookie(context.getChooser().getClientCookie());
            getObject()
                    .setKeyExchangeAlgorithms(
                            context.getChooser().getClientSupportedKeyExchangeAlgorithms(), true);
            getObject()
                    .setServerHostKeyAlgorithms(
                            context.getChooser().getClientSupportedHostKeyAlgorithms(), true);
            getObject()
                    .setEncryptionAlgorithmsClientToServer(
                            context.getChooser().getClientSupportedCipherAlgorithmsClientToServer(),
                            true);
            getObject()
                    .setEncryptionAlgorithmsServerToClient(
                            context.getChooser().getClientSupportedCipherAlgorithmsServerToClient(),
                            true);
            getObject()
                    .setMacAlgorithmsClientToServer(
                            context.getChooser().getClientSupportedMacAlgorithmsClientToServer(),
                            true);
            getObject()
                    .setMacAlgorithmsServerToClient(
                            context.getChooser().getClientSupportedMacAlgorithmsServerToClient(),
                            true);
            getObject()
                    .setCompressionAlgorithmsClientToServer(
                            context.getChooser()
                                    .getClientSupportedCompressionAlgorithmsClientToServer(),
                            true);
            getObject()
                    .setCompressionAlgorithmsServerToClient(
                            context.getChooser()
                                    .getClientSupportedCompressionAlgorithmsServerToClient(),
                            true);
            getObject()
                    .setLanguagesClientToServer(
                            context.getChooser()
                                    .getClientSupportedLanguagesClientToServer()
                                    .toArray(new String[0]),
                            true);
            getObject()
                    .setLanguagesServerToClient(
                            context.getChooser()
                                    .getClientSupportedLanguagesServerToClient()
                                    .toArray(new String[0]),
                            true);
            getObject()
                    .setFirstKeyExchangePacketFollows(
                            context.getChooser().getClientFirstKeyExchangePacketFollows());
            getObject().setReserved(context.getChooser().getClientReserved());

            context.getExchangeHashInstance().setClientKeyExchangeInit(getObject());
        } else {
            getObject().setCookie(context.getChooser().getServerCookie());
            getObject()
                    .setKeyExchangeAlgorithms(
                            context.getChooser().getServerSupportedKeyExchangeAlgorithms(), true);
            getObject()
                    .setServerHostKeyAlgorithms(
                            context.getChooser().getServerSupportedHostKeyAlgorithms(), true);
            getObject()
                    .setEncryptionAlgorithmsClientToServer(
                            context.getChooser().getServerSupportedCipherAlgorithmsClientToServer(),
                            true);
            getObject()
                    .setEncryptionAlgorithmsServerToClient(
                            context.getChooser().getServerSupportedCipherAlgorithmsServerToClient(),
                            true);
            getObject()
                    .setMacAlgorithmsClientToServer(
                            context.getChooser().getServerSupportedMacAlgorithmsClientToServer(),
                            true);
            getObject()
                    .setMacAlgorithmsServerToClient(
                            context.getChooser().getServerSupportedMacAlgorithmsServerToClient(),
                            true);
            getObject()
                    .setCompressionAlgorithmsClientToServer(
                            context.getChooser()
                                    .getServerSupportedCompressionAlgorithmsClientToServer(),
                            true);
            getObject()
                    .setCompressionAlgorithmsServerToClient(
                            context.getChooser()
                                    .getServerSupportedCompressionAlgorithmsServerToClient(),
                            true);
            getObject()
                    .setLanguagesClientToServer(
                            context.getChooser()
                                    .getServerSupportedLanguagesClientToServer()
                                    .toArray(new String[0]),
                            true);
            getObject()
                    .setLanguagesServerToClient(
                            context.getChooser()
                                    .getServerSupportedLanguagesServerToClient()
                                    .toArray(new String[0]),
                            true);
            getObject()
                    .setFirstKeyExchangePacketFollows(
                            context.getChooser().getServerFirstKeyExchangePacketFollows());
            getObject().setReserved(context.getChooser().getServerReserved());

            context.getExchangeHashInstance().setServerKeyExchangeInit(getObject());
        }
    }
}
