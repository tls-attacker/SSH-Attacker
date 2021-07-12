/**
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2021 Ruhr University Bochum, Paderborn University,
 * and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.preparator;

import de.rub.nds.sshattacker.core.constants.CharConstants;
import de.rub.nds.sshattacker.core.constants.MessageIDConstant;
import de.rub.nds.sshattacker.core.protocol.serializer.KeyExchangeInitMessageSerializer;
import de.rub.nds.sshattacker.core.util.Converter;
import de.rub.nds.sshattacker.core.protocol.message.KeyExchangeInitMessage;
import de.rub.nds.sshattacker.core.state.SshContext;

public class KeyExchangeInitMessagePreparator extends Preparator<KeyExchangeInitMessage> {

    public KeyExchangeInitMessagePreparator(SshContext context, KeyExchangeInitMessage message) {
        super(context, message);
    }

    @Override
    public void prepare() {
        message.setMessageID(MessageIDConstant.SSH_MSG_KEXINIT.id);
        if (context.isClient()) {
            message.setCookie(context.getChooser().getClientCookie());
            message.setKeyExchangeAlgorithms(Converter.listOfAlgorithmsToString(context.getChooser()
                    .getClientSupportedKeyExchangeAlgorithms()));
            message.setKeyExchangeAlgorithmsLength(message.getKeyExchangeAlgorithms().getValue().length());
            message.setServerHostKeyAlgorithms(Converter.listOfAlgorithmsToString(context.getChooser()
                    .getClientSupportedHostKeyAlgorithms()));
            message.setServerHostKeyAlgorithmsLength(message.getServerHostKeyAlgorithms().getValue().length());
            message.setEncryptionAlgorithmsClientToServer(Converter.listOfAlgorithmsToString(context.getChooser()
                    .getClientSupportedCipherAlgorithmsClientToServer()));
            message.setEncryptionAlgorithmsClientToServerLength(message.getEncryptionAlgorithmsClientToServer()
                    .getValue().length());
            message.setEncryptionAlgorithmsServerToClient(Converter.listOfAlgorithmsToString(context.getChooser()
                    .getClientSupportedCipherAlgorithmsServerToClient()));
            message.setEncryptionAlgorithmsServerToClientLength(message.getEncryptionAlgorithmsServerToClient()
                    .getValue().length());
            message.setMacAlgorithmsClientToServer(Converter.listOfAlgorithmsToString(context.getChooser()
                    .getClientSupportedMacAlgorithmsClientToServer()));
            message.setMacAlgorithmsClientToServerLength(message.getMacAlgorithmsClientToServer().getValue().length());
            message.setMacAlgorithmsServerToClient(Converter.listOfAlgorithmsToString(context.getChooser()
                    .getClientSupportedMacAlgorithmsServerToClient()));
            message.setMacAlgorithmsServerToClientLength(message.getMacAlgorithmsServerToClient().getValue().length());
            message.setCompressionAlgorithmsClientToServer(Converter.listOfAlgorithmsToString(context.getChooser()
                    .getClientSupportedCompressionAlgorithmsClientToServer()));
            message.setCompressionAlgorithmsClientToServerLength(message.getCompressionAlgorithmsClientToServer()
                    .getValue().length());
            message.setCompressionAlgorithmsServerToClient(Converter.listOfAlgorithmsToString(context.getChooser()
                    .getClientSupportedCompressionAlgorithmsServerToClient()));
            message.setCompressionAlgorithmsServerToClientLength(message.getCompressionAlgorithmsServerToClient()
                    .getValue().length());
            message.setLanguagesClientToServer(Converter.joinStringList(context.getChooser()
                    .getClientSupportedLanguagesClientToServer(), CharConstants.ALGORITHM_SEPARATOR));
            message.setLanguagesClientToServerLength(message.getLanguagesClientToServer().getValue().length());
            message.setLanguagesServerToClient(Converter.joinStringList(context.getChooser()
                    .getClientSupportedLanguagesServerToClient(), CharConstants.ALGORITHM_SEPARATOR));
            message.setLanguagesServerToClientLength(message.getLanguagesServerToClient().getValue().length());
            message.setFirstKeyExchangePacketFollows(context.getChooser().getClientFirstKeyExchangePacketFollows());
            message.setReserved(context.getChooser().getClientReserved());

            context.getExchangeHashInstance().setClientKeyExchangeInit(message);
        } else {
            message.setCookie(context.getChooser().getServerCookie());
            message.setKeyExchangeAlgorithms(Converter.listOfAlgorithmsToString(context.getChooser()
                    .getServerSupportedKeyExchangeAlgorithms()));
            message.setKeyExchangeAlgorithmsLength(message.getKeyExchangeAlgorithms().getValue().length());
            message.setServerHostKeyAlgorithms(Converter.listOfAlgorithmsToString(context.getChooser()
                    .getServerSupportedHostKeyAlgorithms()));
            message.setServerHostKeyAlgorithmsLength(message.getServerHostKeyAlgorithms().getValue().length());
            message.setEncryptionAlgorithmsClientToServer(Converter.listOfAlgorithmsToString(context.getChooser()
                    .getServerSupportedCipherAlgorithmsClientToServer()));
            message.setEncryptionAlgorithmsClientToServerLength(message.getEncryptionAlgorithmsClientToServer()
                    .getValue().length());
            message.setEncryptionAlgorithmsServerToClient(Converter.listOfAlgorithmsToString(context.getChooser()
                    .getServerSupportedCipherAlgorithmsServerToClient()));
            message.setEncryptionAlgorithmsServerToClientLength(message.getEncryptionAlgorithmsServerToClient()
                    .getValue().length());
            message.setMacAlgorithmsClientToServer(Converter.listOfAlgorithmsToString(context.getChooser()
                    .getServerSupportedMacAlgorithmsClientToServer()));
            message.setMacAlgorithmsClientToServerLength(message.getMacAlgorithmsClientToServer().getValue().length());
            message.setMacAlgorithmsServerToClient(Converter.listOfAlgorithmsToString(context.getChooser()
                    .getServerSupportedMacAlgorithmsServerToClient()));
            message.setMacAlgorithmsServerToClientLength(message.getMacAlgorithmsServerToClient().getValue().length());
            message.setCompressionAlgorithmsClientToServer(Converter.listOfAlgorithmsToString(context.getChooser()
                    .getServerSupportedCompressionAlgorithmsClientToServer()));
            message.setCompressionAlgorithmsClientToServerLength(message.getCompressionAlgorithmsClientToServer()
                    .getValue().length());
            message.setCompressionAlgorithmsServerToClient(Converter.listOfAlgorithmsToString(context.getChooser()
                    .getServerSupportedCompressionAlgorithmsServerToClient()));
            message.setCompressionAlgorithmsServerToClientLength(message.getCompressionAlgorithmsServerToClient()
                    .getValue().length());
            message.setLanguagesClientToServer(Converter.joinStringList(context.getChooser()
                    .getServerSupportedLanguagesClientToServer(), CharConstants.ALGORITHM_SEPARATOR));
            message.setLanguagesClientToServerLength(message.getLanguagesClientToServer().getValue().length());
            message.setLanguagesServerToClient(Converter.joinStringList(context.getChooser()
                    .getServerSupportedLanguagesServerToClient(), CharConstants.ALGORITHM_SEPARATOR));
            message.setLanguagesServerToClientLength(message.getLanguagesServerToClient().getValue().length());
            message.setFirstKeyExchangePacketFollows(context.getChooser().getServerFirstKeyExchangePacketFollows());
            message.setReserved(context.getChooser().getServerReserved());

            context.getExchangeHashInstance().setServerKeyExchangeInit(message);
        }
    }
}
