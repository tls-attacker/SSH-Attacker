/**
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2021 Ruhr University Bochum, Paderborn University,
 * and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.protocol.handler;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.sshattacker.constants.CompressionAlgorithm;
import de.rub.nds.sshattacker.constants.EncryptionAlgorithm;
import de.rub.nds.sshattacker.constants.KeyExchangeAlgorithm;
import de.rub.nds.sshattacker.constants.Language;
import de.rub.nds.sshattacker.constants.MacAlgorithm;
import de.rub.nds.sshattacker.constants.MessageIDConstant;
import de.rub.nds.sshattacker.constants.PublicKeyAuthenticationAlgorithm;
import de.rub.nds.sshattacker.protocol.AlgorithmPicker;
import de.rub.nds.sshattacker.protocol.message.KeyExchangeInitMessage;
import de.rub.nds.sshattacker.protocol.serializer.KeyExchangeInitMessageSerializer;
import de.rub.nds.sshattacker.state.SshContext;
import de.rub.nds.sshattacker.util.Converter;

public class KeyExchangeInitMessageHandler extends Handler<KeyExchangeInitMessage> {

    public KeyExchangeInitMessageHandler(SshContext context) {
        super(context);
    }

    @Override
    public void handle(KeyExchangeInitMessage message) {
        context.setServerCookie(message.getCookie().getValue());
        context.setServerSupportedKeyExchangeAlgorithms(Converter.stringToAlgorithms(message.getKeyExchangeAlgorithms()
                .getValue(), KeyExchangeAlgorithm.class));
        context.setServerSupportedHostKeyAlgorithms(Converter.stringToAlgorithms(message.getServerHostKeyAlgorithms()
                .getValue(), PublicKeyAuthenticationAlgorithm.class));
        context.setServerSupportedCipherAlgorithmsClientToServer(Converter.stringToAlgorithms(message
                .getEncryptionAlgorithmsClientToServer().getValue(), EncryptionAlgorithm.class));
        context.setServerSupportedCipherAlgorithmsServerToClient(Converter.stringToAlgorithms(message
                .getEncryptionAlgorithmsServerToClient().getValue(), EncryptionAlgorithm.class));
        context.setServerSupportedMacAlgorithmsClientToServer(Converter.stringToAlgorithms(message
                .getMacAlgorithmsClientToServer().getValue(), MacAlgorithm.class));
        context.setServerSupportedMacAlgorithmsServerToClient(Converter.stringToAlgorithms(message
                .getMacAlgorithmsServerToClient().getValue(), MacAlgorithm.class));
        context.setServerSupportedCompressionAlgorithmsClientToServer(Converter.stringToAlgorithms(message
                .getCompressionAlgorithmsClientToServer().getValue(), CompressionAlgorithm.class));
        context.setServerSupportedCompressionAlgorithmsServerToClient(Converter.stringToAlgorithms(message
                .getCompressionAlgorithmsServerToClient().getValue(), CompressionAlgorithm.class));
        context.setServerSupportedLanguagesClientToServer(Converter.stringToAlgorithms(message
                .getLanguagesClientToServer().getValue(), Language.class));
        context.setServerSupportedLanguagesServerToClient(Converter.stringToAlgorithms(message
                .getLanguagesServerToClient().getValue(), Language.class));
        context.setServerReserved(message.getReserved().getValue());

        adjustAlgorithms();

        context.appendToExchangeHashInput(ArrayConverter.concatenate(
                new byte[] { MessageIDConstant.SSH_MSG_KEXINIT.id },
                new KeyExchangeInitMessageSerializer(message).serializeMessageSpecificPayload()));

    }

    private void adjustAlgorithms() {
        // if enforceSettings is true, the algorithms are expected to be
        // already set in the context
        if (!context.getConfig().getEnforceSettings()) {
            context.setKeyExchangeAlgorithm(AlgorithmPicker.pickAlgorithm(
                    context.getChooser().getClientSupportedKeyExchangeAlgorithms(),
                    context.getChooser().getServerSupportedKeyExchangeAlgorithms()).orElse(null));

            context.setCipherAlgorithmClientToServer(AlgorithmPicker.pickAlgorithm(
                    context.getChooser().getClientSupportedCipherAlgorithmsClientToServer(),
                    context.getChooser().getServerSupportedCipherAlgorithmsClientToServer()).orElse(null));

            context.setCipherAlgorithmServerToClient(AlgorithmPicker.pickAlgorithm(
                    context.getChooser().getClientSupportedCipherAlgorithmsServertoClient(),
                    context.getChooser().getServerSupportedCipherAlgorithmsServerToClient()).orElse(null));

            context.setServerHostKeyAlgorithm(AlgorithmPicker.pickAlgorithm(
                    context.getChooser().getClientSupportedHostKeyAlgorithms(),
                    context.getChooser().getServerSupportedHostKeyAlgorithms()).orElse(null));

            context.setMacAlgorithmClientToServer(AlgorithmPicker.pickAlgorithm(
                    context.getChooser().getClientSupportedMacAlgorithmsClientToServer(),
                    context.getChooser().getServerSupportedMacAlgorithmsClientToServer()).orElse(null));

            context.setMacAlgorithmServerToClient(AlgorithmPicker.pickAlgorithm(
                    context.getChooser().getClientSupportedMacAlgorithmsServerToClient(),
                    context.getChooser().getServerSupportedMacAlgorithmsServerToClient()).orElse(null));

            context.setCompressionAlgorithmClientToServer(AlgorithmPicker.pickAlgorithm(
                    context.getChooser().getClientSupportedCompressionAlgorithmsClientToServer(),
                    context.getChooser().getServerSupportedCompressionAlgorithmsClientToServer()).orElse(null));

            context.setCompressionAlgorithmServerToClient(AlgorithmPicker.pickAlgorithm(
                    context.getChooser().getClientSupportedCompressionAlgorithmsServerToClient(),
                    context.getChooser().getServerSupportedCompressionAlgorithmsServerToClient()).orElse(null));

            context.setLanguageClientToServer(AlgorithmPicker.pickAlgorithm(
                    context.getChooser().getClientSupportedLanguagesClientToServer(),
                    context.getChooser().getServerSupportedLanguagesServerToClient()).orElse(null));

            context.setLanguageServerToClient(AlgorithmPicker.pickAlgorithm(
                    context.getChooser().getClientSupportedLanguagesServerToClient(),
                    context.getChooser().getServerSupportedLanguagesServerToClient()).orElse(null));
        }
    }
}
