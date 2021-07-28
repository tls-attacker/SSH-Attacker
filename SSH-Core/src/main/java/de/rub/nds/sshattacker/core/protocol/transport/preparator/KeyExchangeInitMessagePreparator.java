/**
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * <p>Copyright 2014-2021 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * <p>Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.transport.preparator;

import de.rub.nds.sshattacker.core.constants.MessageIDConstant;
import de.rub.nds.sshattacker.core.protocol.common.Preparator;
import de.rub.nds.sshattacker.core.protocol.transport.message.KeyExchangeInitMessage;
import de.rub.nds.sshattacker.core.state.SshContext;

public class KeyExchangeInitMessagePreparator extends Preparator<KeyExchangeInitMessage> {

    public KeyExchangeInitMessagePreparator(SshContext context, KeyExchangeInitMessage message) {
        super(context, message);
    }

    @Override
    public void prepare() {
        message.setMessageID(MessageIDConstant.SSH_MSG_KEXINIT);
        if (context.isClient()) {
            message.setCookie(context.getChooser().getClientCookie());
            message.setKeyExchangeAlgorithms(
                    context.getChooser().getClientSupportedKeyExchangeAlgorithms(), true);
            message.setServerHostKeyAlgorithms(
                    context.getChooser().getClientSupportedHostKeyAlgorithms(), true);
            message.setEncryptionAlgorithmsClientToServer(
                    context.getChooser().getClientSupportedCipherAlgorithmsClientToServer(), true);
            message.setEncryptionAlgorithmsServerToClient(
                    context.getChooser().getClientSupportedCipherAlgorithmsServerToClient(), true);
            message.setMacAlgorithmsClientToServer(
                    context.getChooser().getClientSupportedMacAlgorithmsClientToServer(), true);
            message.setMacAlgorithmsServerToClient(
                    context.getChooser().getClientSupportedMacAlgorithmsServerToClient(), true);
            message.setCompressionAlgorithmsClientToServer(
                    context.getChooser().getClientSupportedCompressionAlgorithmsClientToServer(),
                    true);
            message.setCompressionAlgorithmsServerToClient(
                    context.getChooser().getClientSupportedCompressionAlgorithmsServerToClient(),
                    true);
            message.setLanguagesClientToServer(
                    context.getChooser()
                            .getClientSupportedLanguagesClientToServer()
                            .toArray(new String[0]),
                    true);
            message.setLanguagesServerToClient(
                    context.getChooser()
                            .getClientSupportedLanguagesServerToClient()
                            .toArray(new String[0]),
                    true);
            message.setFirstKeyExchangePacketFollows(
                    context.getChooser().getClientFirstKeyExchangePacketFollows());
            message.setReserved(context.getChooser().getClientReserved());

            context.getExchangeHashInstance().setClientKeyExchangeInit(message);
        } else {
            message.setCookie(context.getChooser().getServerCookie());
            message.setKeyExchangeAlgorithms(
                    context.getChooser().getServerSupportedKeyExchangeAlgorithms(), true);
            message.setServerHostKeyAlgorithms(
                    context.getChooser().getServerSupportedHostKeyAlgorithms(), true);
            message.setEncryptionAlgorithmsClientToServer(
                    context.getChooser().getServerSupportedCipherAlgorithmsClientToServer(), true);
            message.setEncryptionAlgorithmsServerToClient(
                    context.getChooser().getServerSupportedCipherAlgorithmsServerToClient(), true);
            message.setMacAlgorithmsClientToServer(
                    context.getChooser().getServerSupportedMacAlgorithmsClientToServer(), true);
            message.setMacAlgorithmsServerToClient(
                    context.getChooser().getServerSupportedMacAlgorithmsServerToClient(), true);
            message.setCompressionAlgorithmsClientToServer(
                    context.getChooser().getServerSupportedCompressionAlgorithmsClientToServer(),
                    true);
            message.setCompressionAlgorithmsServerToClient(
                    context.getChooser().getServerSupportedCompressionAlgorithmsServerToClient(),
                    true);
            message.setLanguagesClientToServer(
                    context.getChooser()
                            .getServerSupportedLanguagesClientToServer()
                            .toArray(new String[0]),
                    true);
            message.setLanguagesServerToClient(
                    context.getChooser()
                            .getServerSupportedLanguagesServerToClient()
                            .toArray(new String[0]),
                    true);
            message.setFirstKeyExchangePacketFollows(
                    context.getChooser().getServerFirstKeyExchangePacketFollows());
            message.setReserved(context.getChooser().getServerReserved());

            context.getExchangeHashInstance().setServerKeyExchangeInit(message);
        }
    }
}
