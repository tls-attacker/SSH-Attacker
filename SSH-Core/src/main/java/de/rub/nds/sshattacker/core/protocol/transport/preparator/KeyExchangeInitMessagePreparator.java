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
        Config config = chooser.getConfig();
        if (chooser.getContext().isClient()) {
            object.setSoftlyCookie(chooser.getClientCookie(), config);
            object.setSoftlyKeyExchangeAlgorithms(
                    chooser.getClientSupportedKeyExchangeAlgorithms(), true, config);
            object.setSoftlyServerHostKeyAlgorithms(
                    chooser.getClientSupportedHostKeyAlgorithms(), true, config);
            object.setSoftlyEncryptionAlgorithmsClientToServer(
                    chooser.getClientSupportedEncryptionAlgorithmsClientToServer(),
                    true, config);
            object.setSoftlyEncryptionAlgorithmsServerToClient(
                    chooser.getClientSupportedEncryptionAlgorithmsServerToClient(),
                    true, config);
            object.setSoftlyMacAlgorithmsClientToServer(
                    chooser.getClientSupportedMacAlgorithmsClientToServer(),
                    true, config);
            object.setSoftlyMacAlgorithmsServerToClient(
                    chooser.getClientSupportedMacAlgorithmsServerToClient(),
                    true, config);
            object.setSoftlyCompressionMethodsClientToServer(
                    chooser.getClientSupportedCompressionMethodsClientToServer(),
                    true, config);
            object.setSoftlyCompressionMethodsServerToClient(
                    chooser.getClientSupportedCompressionMethodsServerToClient(),
                    true, config);
            object.setSoftlyLanguagesClientToServer(
                    chooser.getClientSupportedLanguagesClientToServer(), true, config);
            object.setSoftlyLanguagesServerToClient(
                    chooser.getClientSupportedLanguagesServerToClient(), true, config);
            object.setSoftlyFirstKeyExchangePacketFollows(
                    chooser.getClientFirstKeyExchangePacketFollows(), config);
            object.setSoftlyReserved(chooser.getClientReserved(), config);

            chooser.getContext().getExchangeHashInputHolder().setClientKeyExchangeInit(object);
        } else {
            object.setSoftlyCookie(chooser.getServerCookie(), config);
            object.setSoftlyKeyExchangeAlgorithms(
                    chooser.getServerSupportedKeyExchangeAlgorithms(), true, config);
            object.setSoftlyServerHostKeyAlgorithms(
                    chooser.getServerSupportedHostKeyAlgorithms(), true, config);
            object.setSoftlyEncryptionAlgorithmsClientToServer(
                    chooser.getServerSupportedEncryptionAlgorithmsClientToServer(),
                    true, config);
            object.setSoftlyEncryptionAlgorithmsServerToClient(
                    chooser.getServerSupportedEncryptionAlgorithmsServerToClient(),
                    true, config);
            object.setSoftlyMacAlgorithmsClientToServer(
                    chooser.getServerSupportedMacAlgorithmsClientToServer(),
                    true, config);
            object.setSoftlyMacAlgorithmsServerToClient(
                    chooser.getServerSupportedMacAlgorithmsServerToClient(),
                    true, config);
            object.setSoftlyCompressionMethodsClientToServer(
                    chooser.getServerSupportedCompressionMethodsClientToServer(),
                    true, config);
            object.setSoftlyCompressionMethodsServerToClient(
                    chooser.getServerSupportedCompressionMethodsServerToClient(),
                    true, config);
            object.setSoftlyLanguagesClientToServer(
                    chooser.getServerSupportedLanguagesClientToServer(), true, config);
            object.setSoftlyLanguagesServerToClient(
                    chooser.getServerSupportedLanguagesServerToClient(), true, config);
            object.setSoftlyFirstKeyExchangePacketFollows(
                    chooser.getServerFirstKeyExchangePacketFollows(), config);
            object.setSoftlyReserved(chooser.getServerReserved(), config);

            chooser.getContext().getExchangeHashInputHolder().setServerKeyExchangeInit(object);
        }
    }
}
