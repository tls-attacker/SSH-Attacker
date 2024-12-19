/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.transport.preparator;

import de.rub.nds.sshattacker.core.constants.MessageIdConstant;
import de.rub.nds.sshattacker.core.protocol.common.SshMessagePreparator;
import de.rub.nds.sshattacker.core.protocol.transport.message.KeyExchangeInitMessage;
import de.rub.nds.sshattacker.core.workflow.chooser.Chooser;

public class KeyExchangeInitMessagePreparator extends SshMessagePreparator<KeyExchangeInitMessage> {

    public KeyExchangeInitMessagePreparator(Chooser chooser, KeyExchangeInitMessage message) {
        super(chooser, message, MessageIdConstant.SSH_MSG_KEXINIT);
    }

    @Override
    public void prepareMessageSpecificContents() {
        if (chooser.getContext().isClient()) {
            getObject().setSoftlyCookie(chooser.getClientCookie(), chooser.getConfig());
            getObject()
                    .setSoftlyKeyExchangeAlgorithms(
                            chooser.getClientSupportedKeyExchangeAlgorithms(),
                            true,
                            chooser.getConfig());
            getObject()
                    .setSoftlyServerHostKeyAlgorithms(
                            chooser.getClientSupportedHostKeyAlgorithms(),
                            true,
                            chooser.getConfig());
            getObject()
                    .setSoftlyEncryptionAlgorithmsClientToServer(
                            chooser.getClientSupportedEncryptionAlgorithmsClientToServer(),
                            true,
                            chooser.getConfig());
            getObject()
                    .setSoftlyEncryptionAlgorithmsServerToClient(
                            chooser.getClientSupportedEncryptionAlgorithmsServerToClient(),
                            true,
                            chooser.getConfig());
            getObject()
                    .setSoftlyMacAlgorithmsClientToServer(
                            chooser.getClientSupportedMacAlgorithmsClientToServer(),
                            true,
                            chooser.getConfig());
            getObject()
                    .setSoftlyMacAlgorithmsServerToClient(
                            chooser.getClientSupportedMacAlgorithmsServerToClient(),
                            true,
                            chooser.getConfig());
            getObject()
                    .setSoftlyCompressionMethodsClientToServer(
                            chooser.getClientSupportedCompressionMethodsClientToServer(),
                            true,
                            chooser.getConfig());
            getObject()
                    .setSoftlyCompressionMethodsServerToClient(
                            chooser.getClientSupportedCompressionMethodsServerToClient(),
                            true,
                            chooser.getConfig());
            getObject()
                    .setSoftlyLanguagesClientToServer(
                            chooser.getClientSupportedLanguagesClientToServer(),
                            true,
                            chooser.getConfig());
            getObject()
                    .setSoftlyLanguagesServerToClient(
                            chooser.getClientSupportedLanguagesServerToClient(),
                            true,
                            chooser.getConfig());
            getObject()
                    .setSoftlyFirstKeyExchangePacketFollows(
                            chooser.getClientFirstKeyExchangePacketFollows(), chooser.getConfig());
            getObject().setSoftlyReserved(chooser.getClientReserved(), chooser.getConfig());

            chooser.getContext().getExchangeHashInputHolder().setClientKeyExchangeInit(getObject());
        } else {
            getObject().setSoftlyCookie(chooser.getServerCookie(), chooser.getConfig());
            getObject()
                    .setSoftlyKeyExchangeAlgorithms(
                            chooser.getServerSupportedKeyExchangeAlgorithms(),
                            true,
                            chooser.getConfig());
            getObject()
                    .setSoftlyServerHostKeyAlgorithms(
                            chooser.getServerSupportedHostKeyAlgorithms(),
                            true,
                            chooser.getConfig());
            getObject()
                    .setSoftlyEncryptionAlgorithmsClientToServer(
                            chooser.getServerSupportedEncryptionAlgorithmsClientToServer(),
                            true,
                            chooser.getConfig());
            getObject()
                    .setSoftlyEncryptionAlgorithmsServerToClient(
                            chooser.getServerSupportedEncryptionAlgorithmsServerToClient(),
                            true,
                            chooser.getConfig());
            getObject()
                    .setSoftlyMacAlgorithmsClientToServer(
                            chooser.getServerSupportedMacAlgorithmsClientToServer(),
                            true,
                            chooser.getConfig());
            getObject()
                    .setSoftlyMacAlgorithmsServerToClient(
                            chooser.getServerSupportedMacAlgorithmsServerToClient(),
                            true,
                            chooser.getConfig());
            getObject()
                    .setSoftlyCompressionMethodsClientToServer(
                            chooser.getServerSupportedCompressionMethodsClientToServer(),
                            true,
                            chooser.getConfig());
            getObject()
                    .setSoftlyCompressionMethodsServerToClient(
                            chooser.getServerSupportedCompressionMethodsServerToClient(),
                            true,
                            chooser.getConfig());
            getObject()
                    .setSoftlyLanguagesClientToServer(
                            chooser.getServerSupportedLanguagesClientToServer(),
                            true,
                            chooser.getConfig());
            getObject()
                    .setSoftlyLanguagesServerToClient(
                            chooser.getServerSupportedLanguagesServerToClient(),
                            true,
                            chooser.getConfig());
            getObject()
                    .setSoftlyFirstKeyExchangePacketFollows(
                            chooser.getServerFirstKeyExchangePacketFollows(), chooser.getConfig());
            getObject().setSoftlyReserved(chooser.getServerReserved(), chooser.getConfig());

            chooser.getContext().getExchangeHashInputHolder().setServerKeyExchangeInit(getObject());
        }
    }
}
