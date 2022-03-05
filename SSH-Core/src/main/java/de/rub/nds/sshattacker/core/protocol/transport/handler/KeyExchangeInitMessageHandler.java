/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.transport.handler;

import de.rub.nds.sshattacker.core.constants.*;
import de.rub.nds.sshattacker.core.protocol.common.*;
import de.rub.nds.sshattacker.core.protocol.transport.message.KeyExchangeInitMessage;
import de.rub.nds.sshattacker.core.protocol.transport.parser.KeyExchangeInitMessageParser;
import de.rub.nds.sshattacker.core.protocol.transport.preparator.KeyExchangeInitMessagePreparator;
import de.rub.nds.sshattacker.core.protocol.transport.serializer.KeyExchangeInitMessageSerializer;
import de.rub.nds.sshattacker.core.protocol.util.AlgorithmPicker;
import de.rub.nds.sshattacker.core.state.SshContext;
import de.rub.nds.sshattacker.core.util.Converter;
import java.util.Arrays;

public class KeyExchangeInitMessageHandler extends SshMessageHandler<KeyExchangeInitMessage> {

    public KeyExchangeInitMessageHandler(SshContext context) {
        super(context);
    }

    public KeyExchangeInitMessageHandler(SshContext context, KeyExchangeInitMessage message) {
        super(context, message);
    }

    @Override
    public void adjustContext() {
        if (context.isClient()) {
            context.setServerCookie(message.getCookie().getValue());
            context.setServerSupportedKeyExchangeAlgorithms(
                    Converter.nameListToEnumValues(
                            message.getKeyExchangeAlgorithms().getValue(),
                            KeyExchangeAlgorithm.class));
            context.setServerSupportedHostKeyAlgorithms(
                    Converter.nameListToEnumValues(
                            message.getServerHostKeyAlgorithms().getValue(),
                            PublicKeyAuthenticationAlgorithm.class));
            context.setServerSupportedCipherAlgorithmsClientToServer(
                    Converter.nameListToEnumValues(
                            message.getEncryptionAlgorithmsClientToServer().getValue(),
                            EncryptionAlgorithm.class));
            context.setServerSupportedCipherAlgorithmsServerToClient(
                    Converter.nameListToEnumValues(
                            message.getEncryptionAlgorithmsServerToClient().getValue(),
                            EncryptionAlgorithm.class));
            context.setServerSupportedMacAlgorithmsClientToServer(
                    Converter.nameListToEnumValues(
                            message.getMacAlgorithmsClientToServer().getValue(),
                            MacAlgorithm.class));
            context.setServerSupportedMacAlgorithmsServerToClient(
                    Converter.nameListToEnumValues(
                            message.getMacAlgorithmsServerToClient().getValue(),
                            MacAlgorithm.class));
            context.setServerSupportedCompressionMethodsClientToServer(
                    Converter.nameListToEnumValues(
                            message.getCompressionMethodsClientToServer().getValue(),
                            CompressionMethod.class));
            context.setServerSupportedCompressionMethodsServerToClient(
                    Converter.nameListToEnumValues(
                            message.getCompressionMethodsServerToClient().getValue(),
                            CompressionMethod.class));
            context.setServerSupportedLanguagesClientToServer(
                    Arrays.asList(
                            message.getLanguagesClientToServer()
                                    .getValue()
                                    .split("" + CharConstants.ALGORITHM_SEPARATOR)));
            context.setServerSupportedLanguagesServerToClient(
                    Arrays.asList(
                            message.getLanguagesServerToClient()
                                    .getValue()
                                    .split("" + CharConstants.ALGORITHM_SEPARATOR)));
            context.setServerReserved(message.getReserved().getValue());

            context.getExchangeHashInstance().setServerKeyExchangeInit(message);
        } else {
            context.setClientCookie(message.getCookie().getValue());
            context.setClientSupportedKeyExchangeAlgorithms(
                    Converter.nameListToEnumValues(
                            message.getKeyExchangeAlgorithms().getValue(),
                            KeyExchangeAlgorithm.class));
            context.setClientSupportedHostKeyAlgorithms(
                    Converter.nameListToEnumValues(
                            message.getServerHostKeyAlgorithms().getValue(),
                            PublicKeyAuthenticationAlgorithm.class));
            context.setClientSupportedCipherAlgorithmsClientToServer(
                    Converter.nameListToEnumValues(
                            message.getEncryptionAlgorithmsClientToServer().getValue(),
                            EncryptionAlgorithm.class));
            context.setClientSupportedCipherAlgorithmsServerToClient(
                    Converter.nameListToEnumValues(
                            message.getEncryptionAlgorithmsServerToClient().getValue(),
                            EncryptionAlgorithm.class));
            context.setClientSupportedMacAlgorithmsClientToServer(
                    Converter.nameListToEnumValues(
                            message.getMacAlgorithmsClientToServer().getValue(),
                            MacAlgorithm.class));
            context.setClientSupportedMacAlgorithmsServerToClient(
                    Converter.nameListToEnumValues(
                            message.getMacAlgorithmsServerToClient().getValue(),
                            MacAlgorithm.class));
            context.setClientSupportedCompressionMethodsClientToServer(
                    Converter.nameListToEnumValues(
                            message.getCompressionMethodsClientToServer().getValue(),
                            CompressionMethod.class));
            context.setClientSupportedCompressionMethodsServerToClient(
                    Converter.nameListToEnumValues(
                            message.getCompressionMethodsServerToClient().getValue(),
                            CompressionMethod.class));
            context.setClientSupportedLanguagesClientToServer(
                    Arrays.asList(
                            message.getLanguagesClientToServer()
                                    .getValue()
                                    .split("" + CharConstants.ALGORITHM_SEPARATOR)));
            context.setClientSupportedLanguagesServerToClient(
                    Arrays.asList(
                            message.getLanguagesServerToClient()
                                    .getValue()
                                    .split("" + CharConstants.ALGORITHM_SEPARATOR)));
            context.setClientReserved(message.getReserved().getValue());

            context.getExchangeHashInstance().setClientKeyExchangeInit(message);
        }

        pickAlgorithms();
    }

    private void pickAlgorithms() {
        // if enforceSettings is true, the algorithms are expected to be
        // already set in the context
        if (!context.getConfig().getEnforceSettings()) {
            context.setKeyExchangeAlgorithm(
                    AlgorithmPicker.pickAlgorithm(
                                    context.getChooser().getClientSupportedKeyExchangeAlgorithms(),
                                    context.getChooser().getServerSupportedKeyExchangeAlgorithms())
                            .orElse(null));

            context.setCipherAlgorithmClientToServer(
                    AlgorithmPicker.pickAlgorithm(
                                    context.getChooser()
                                            .getClientSupportedCipherAlgorithmsClientToServer(),
                                    context.getChooser()
                                            .getServerSupportedCipherAlgorithmsClientToServer())
                            .orElse(null));

            context.setCipherAlgorithmServerToClient(
                    AlgorithmPicker.pickAlgorithm(
                                    context.getChooser()
                                            .getClientSupportedCipherAlgorithmsServerToClient(),
                                    context.getChooser()
                                            .getServerSupportedCipherAlgorithmsServerToClient())
                            .orElse(null));

            context.setServerHostKeyAlgorithm(
                    AlgorithmPicker.pickAlgorithm(
                                    context.getChooser().getClientSupportedHostKeyAlgorithms(),
                                    context.getChooser().getServerSupportedHostKeyAlgorithms())
                            .orElse(null));

            context.setMacAlgorithmClientToServer(
                    AlgorithmPicker.pickAlgorithm(
                                    context.getChooser()
                                            .getClientSupportedMacAlgorithmsClientToServer(),
                                    context.getChooser()
                                            .getServerSupportedMacAlgorithmsClientToServer())
                            .orElse(null));

            context.setMacAlgorithmServerToClient(
                    AlgorithmPicker.pickAlgorithm(
                                    context.getChooser()
                                            .getClientSupportedMacAlgorithmsServerToClient(),
                                    context.getChooser()
                                            .getServerSupportedMacAlgorithmsServerToClient())
                            .orElse(null));

            context.setCompressionMethodClientToServer(
                    AlgorithmPicker.pickAlgorithm(
                                    context.getChooser()
                                            .getClientSupportedCompressionMethodsClientToServer(),
                                    context.getChooser()
                                            .getServerSupportedCompressionMethodsClientToServer())
                            .orElse(null));

            context.setCompressionMethodServerToClient(
                    AlgorithmPicker.pickAlgorithm(
                                    context.getChooser()
                                            .getClientSupportedCompressionMethodsServerToClient(),
                                    context.getChooser()
                                            .getServerSupportedCompressionMethodsServerToClient())
                            .orElse(null));
        }
    }

    @Override
    public KeyExchangeInitMessageParser getParser(byte[] array, int startPosition) {
        return new KeyExchangeInitMessageParser(array, startPosition);
    }

    @Override
    public KeyExchangeInitMessagePreparator getPreparator() {
        return new KeyExchangeInitMessagePreparator(context.getChooser(), message);
    }

    @Override
    public KeyExchangeInitMessageSerializer getSerializer() {
        return new KeyExchangeInitMessageSerializer(message);
    }
}
