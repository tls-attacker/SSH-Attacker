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
import de.rub.nds.sshattacker.core.workflow.chooser.Chooser;

public class KeyExchangeInitMessagePreparator extends SshMessagePreparator<KeyExchangeInitMessage> {

    public KeyExchangeInitMessagePreparator(Chooser chooser, KeyExchangeInitMessage message) {
        super(chooser, message);
    }

    @Override
    public void prepareMessageSpecificContents() {
        getObject().setMessageID(MessageIDConstant.SSH_MSG_KEXINIT);
        if (chooser.getContext().isClient()) {
            getObject().setCookie(chooser.getClientCookie());
            getObject()
                    .setKeyExchangeAlgorithms(
                            chooser.getClientSupportedKeyExchangeAlgorithms(), true);
            getObject()
                    .setServerHostKeyAlgorithms(
                            chooser.getClientSupportedHostKeyAlgorithms(), true);
            getObject()
                    .setEncryptionAlgorithmsClientToServer(
                            chooser.getClientSupportedCipherAlgorithmsClientToServer(), true);
            getObject()
                    .setEncryptionAlgorithmsServerToClient(
                            chooser.getClientSupportedCipherAlgorithmsServerToClient(), true);
            getObject()
                    .setMacAlgorithmsClientToServer(
                            chooser.getClientSupportedMacAlgorithmsClientToServer(), true);
            getObject()
                    .setMacAlgorithmsServerToClient(
                            chooser.getClientSupportedMacAlgorithmsServerToClient(), true);
            getObject()
                    .setCompressionMethodsClientToServer(
                            chooser.getClientSupportedCompressionMethodsClientToServer(), true);
            getObject()
                    .setCompressionMethodsServerToClient(
                            chooser.getClientSupportedCompressionMethodsServerToClient(), true);
            getObject()
                    .setLanguagesClientToServer(
                            chooser.getClientSupportedLanguagesClientToServer()
                                    .toArray(new String[0]),
                            true);
            getObject()
                    .setLanguagesServerToClient(
                            chooser.getClientSupportedLanguagesServerToClient()
                                    .toArray(new String[0]),
                            true);
            getObject()
                    .setFirstKeyExchangePacketFollows(
                            chooser.getClientFirstKeyExchangePacketFollows());
            getObject().setReserved(chooser.getClientReserved());

            chooser.getContext().getExchangeHashInstance().setClientKeyExchangeInit(getObject());
        } else {
            getObject().setCookie(chooser.getServerCookie());
            getObject()
                    .setKeyExchangeAlgorithms(
                            chooser.getServerSupportedKeyExchangeAlgorithms(), true);
            getObject()
                    .setServerHostKeyAlgorithms(
                            chooser.getServerSupportedHostKeyAlgorithms(), true);
            getObject()
                    .setEncryptionAlgorithmsClientToServer(
                            chooser.getServerSupportedCipherAlgorithmsClientToServer(), true);
            getObject()
                    .setEncryptionAlgorithmsServerToClient(
                            chooser.getServerSupportedCipherAlgorithmsServerToClient(), true);
            getObject()
                    .setMacAlgorithmsClientToServer(
                            chooser.getServerSupportedMacAlgorithmsClientToServer(), true);
            getObject()
                    .setMacAlgorithmsServerToClient(
                            chooser.getServerSupportedMacAlgorithmsServerToClient(), true);
            getObject()
                    .setCompressionMethodsClientToServer(
                            chooser.getServerSupportedCompressionMethodsClientToServer(), true);
            getObject()
                    .setCompressionMethodsServerToClient(
                            chooser.getServerSupportedCompressionMethodsServerToClient(), true);
            getObject()
                    .setLanguagesClientToServer(
                            chooser.getServerSupportedLanguagesClientToServer()
                                    .toArray(new String[0]),
                            true);
            getObject()
                    .setLanguagesServerToClient(
                            chooser.getServerSupportedLanguagesServerToClient()
                                    .toArray(new String[0]),
                            true);
            getObject()
                    .setFirstKeyExchangePacketFollows(
                            chooser.getServerFirstKeyExchangePacketFollows());
            getObject().setReserved(chooser.getServerReserved());

            chooser.getContext().getExchangeHashInstance().setServerKeyExchangeInit(getObject());
        }
    }
}
