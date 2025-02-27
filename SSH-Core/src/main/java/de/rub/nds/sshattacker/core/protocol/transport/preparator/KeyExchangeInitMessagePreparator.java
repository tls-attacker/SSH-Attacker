/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.transport.preparator;

import de.rub.nds.sshattacker.core.config.Config;
import de.rub.nds.sshattacker.core.constants.MessageIdConstant;
import de.rub.nds.sshattacker.core.protocol.common.SshMessagePreparator;
import de.rub.nds.sshattacker.core.protocol.transport.message.KeyExchangeInitMessage;
import de.rub.nds.sshattacker.core.workflow.chooser.Chooser;

public class KeyExchangeInitMessagePreparator extends SshMessagePreparator<KeyExchangeInitMessage> {

    public KeyExchangeInitMessagePreparator() {
        super(MessageIdConstant.SSH_MSG_KEXINIT);
    }

    @Override
    public void prepareMessageSpecificContents(KeyExchangeInitMessage object, Chooser chooser) {
        if (chooser.getContext().isClient()) {
            object.setCookie(chooser.getClientCookie());
            object.setKeyExchangeAlgorithms(
                    chooser.getClientSupportedKeyExchangeAlgorithms(), true);
            object.setServerHostKeyAlgorithms(chooser.getClientSupportedHostKeyAlgorithms(), true);
            object.setEncryptionAlgorithmsClientToServer(
                    chooser.getClientSupportedEncryptionAlgorithmsClientToServer(), true);
            object.setEncryptionAlgorithmsServerToClient(
                    chooser.getClientSupportedEncryptionAlgorithmsServerToClient(), true);
            object.setMacAlgorithmsClientToServer(
                    chooser.getClientSupportedMacAlgorithmsClientToServer(), true);
            object.setMacAlgorithmsServerToClient(
                    chooser.getClientSupportedMacAlgorithmsServerToClient(), true);
            object.setCompressionMethodsClientToServer(
                    chooser.getClientSupportedCompressionMethodsClientToServer(), true);
            object.setCompressionMethodsServerToClient(
                    chooser.getClientSupportedCompressionMethodsServerToClient(), true);
            object.setLanguagesClientToServer(
                    chooser.getClientSupportedLanguagesClientToServer(), true);
            object.setLanguagesServerToClient(
                    chooser.getClientSupportedLanguagesServerToClient(), true);
            object.setFirstKeyExchangePacketFollows(
                    chooser.getClientFirstKeyExchangePacketFollows());
            object.setReserved(chooser.getClientReserved());

            chooser.getContext().getExchangeHashInputHolder().setClientKeyExchangeInit(object);
        } else {
            object.setCookie(chooser.getServerCookie());
            object.setKeyExchangeAlgorithms(
                    chooser.getServerSupportedKeyExchangeAlgorithms(), true);
            object.setServerHostKeyAlgorithms(chooser.getServerSupportedHostKeyAlgorithms(), true);
            object.setEncryptionAlgorithmsClientToServer(
                    chooser.getServerSupportedEncryptionAlgorithmsClientToServer(), true);
            object.setEncryptionAlgorithmsServerToClient(
                    chooser.getServerSupportedEncryptionAlgorithmsServerToClient(), true);
            object.setMacAlgorithmsClientToServer(
                    chooser.getServerSupportedMacAlgorithmsClientToServer(), true);
            object.setMacAlgorithmsServerToClient(
                    chooser.getServerSupportedMacAlgorithmsServerToClient(), true);
            object.setCompressionMethodsClientToServer(
                    chooser.getServerSupportedCompressionMethodsClientToServer(), true);
            object.setCompressionMethodsServerToClient(
                    chooser.getServerSupportedCompressionMethodsServerToClient(), true);
            object.setLanguagesClientToServer(
                    chooser.getServerSupportedLanguagesClientToServer(), true);
            object.setLanguagesServerToClient(
                    chooser.getServerSupportedLanguagesServerToClient(), true);
            object.setFirstKeyExchangePacketFollows(
                    chooser.getServerFirstKeyExchangePacketFollows());
            object.setReserved(chooser.getServerReserved());

            chooser.getContext().getExchangeHashInputHolder().setServerKeyExchangeInit(object);
        }
    }
}
