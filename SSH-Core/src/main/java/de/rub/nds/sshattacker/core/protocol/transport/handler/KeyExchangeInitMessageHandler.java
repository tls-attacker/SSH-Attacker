/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.transport.handler;

import de.rub.nds.sshattacker.core.constants.*;
import de.rub.nds.sshattacker.core.protocol.common.SshMessageHandler;
import de.rub.nds.sshattacker.core.protocol.transport.message.KeyExchangeInitMessage;
import de.rub.nds.sshattacker.core.protocol.transport.parser.KeyExchangeInitMessageParser;
import de.rub.nds.sshattacker.core.protocol.transport.preparator.KeyExchangeInitMessagePreparator;
import de.rub.nds.sshattacker.core.protocol.transport.serializer.KeyExchangeInitMessageSerializer;
import de.rub.nds.sshattacker.core.protocol.util.AlgorithmPicker;
import de.rub.nds.sshattacker.core.state.SshContext;
import de.rub.nds.sshattacker.core.util.Converter;
import java.util.List;

public class KeyExchangeInitMessageHandler extends SshMessageHandler<KeyExchangeInitMessage> {

    public KeyExchangeInitMessageHandler(SshContext context) {
        super(context);
    }

    public KeyExchangeInitMessageHandler(SshContext context, KeyExchangeInitMessage message) {
        super(context, message);
    }

    @Override
    public void adjustContext() {
        if (context.isHandleAsClient()) {
            context.setServerCookie(message.getCookie().getValue());
            context.setServerSupportedKeyExchangeAlgorithms(
                    Converter.nameListToEnumValues(
                            message.getKeyExchangeAlgorithms().getValue(),
                            KeyExchangeAlgorithm.class));
            context.setServerSupportedHostKeyAlgorithms(
                    Converter.nameListToEnumValues(
                            message.getServerHostKeyAlgorithms().getValue(),
                            PublicKeyAlgorithm.class));
            context.setServerSupportedEncryptionAlgorithmsClientToServer(
                    Converter.nameListToEnumValues(
                            message.getEncryptionAlgorithmsClientToServer().getValue(),
                            EncryptionAlgorithm.class));
            context.setServerSupportedEncryptionAlgorithmsServerToClient(
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
                    Converter.nameListStringToStringList(
                            message.getLanguagesClientToServer().getValue()));
            context.setServerSupportedLanguagesServerToClient(
                    Converter.nameListStringToStringList(
                            message.getLanguagesServerToClient().getValue()));
            context.setServerReserved(message.getReserved().getValue());

            context.getExchangeHashInputHolder().setServerKeyExchangeInit(message);

            context.setServerSupportsExtensionNegotiation(
                    checkServerSupportForExtensionNegotiation());
            context.setStrictKeyExchangeEnabled(
                    containsKeyExchangeAlgorithm(
                                    KeyExchangeAlgorithm.KEX_STRICT_S_V00_OPENSSH_COM,
                                    context.getServerSupportedKeyExchangeAlgorithms()
                                            .orElse(List.of()))
                            && containsKeyExchangeAlgorithm(
                                    KeyExchangeAlgorithm.KEX_STRICT_C_V00_OPENSSH_COM,
                                    context.getConfig().getClientSupportedKeyExchangeAlgorithms()));
        } else {
            context.setClientCookie(message.getCookie().getValue());
            context.setClientSupportedKeyExchangeAlgorithms(
                    Converter.nameListToEnumValues(
                            message.getKeyExchangeAlgorithms().getValue(),
                            KeyExchangeAlgorithm.class));
            context.setClientSupportedHostKeyAlgorithms(
                    Converter.nameListToEnumValues(
                            message.getServerHostKeyAlgorithms().getValue(),
                            PublicKeyAlgorithm.class));
            context.setClientSupportedEncryptionAlgorithmsClientToServer(
                    Converter.nameListToEnumValues(
                            message.getEncryptionAlgorithmsClientToServer().getValue(),
                            EncryptionAlgorithm.class));
            context.setClientSupportedEncryptionAlgorithmsServerToClient(
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
                    Converter.nameListStringToStringList(
                            message.getLanguagesClientToServer().getValue()));
            context.setClientSupportedLanguagesServerToClient(
                    Converter.nameListStringToStringList(
                            message.getLanguagesServerToClient().getValue()));
            context.setClientReserved(message.getReserved().getValue());

            context.getExchangeHashInputHolder().setClientKeyExchangeInit(message);

            context.setClientSupportsExtensionNegotiation(
                    checkClientSupportForExtensionNegotiation());
            context.setStrictKeyExchangeEnabled(
                    containsKeyExchangeAlgorithm(
                                    KeyExchangeAlgorithm.KEX_STRICT_C_V00_OPENSSH_COM,
                                    context.getClientSupportedKeyExchangeAlgorithms()
                                            .orElse(List.of()))
                            && containsKeyExchangeAlgorithm(
                                    KeyExchangeAlgorithm.KEX_STRICT_S_V00_OPENSSH_COM,
                                    context.getConfig().getServerSupportedKeyExchangeAlgorithms()));
        }
        pickAlgorithms();
    }

    private boolean checkClientSupportForExtensionNegotiation() {
        return containsKeyExchangeAlgorithm(
                KeyExchangeAlgorithm.EXT_INFO_C,
                context.getClientSupportedKeyExchangeAlgorithms().orElse(List.of()));
    }

    private boolean checkServerSupportForExtensionNegotiation() {
        return containsKeyExchangeAlgorithm(
                KeyExchangeAlgorithm.EXT_INFO_S,
                context.getServerSupportedKeyExchangeAlgorithms().orElse(List.of()));
    }

    private static boolean containsKeyExchangeAlgorithm(
            KeyExchangeAlgorithm keyExchangeAlgorithm, List<KeyExchangeAlgorithm> algorithms) {
        for (KeyExchangeAlgorithm algorithm : algorithms) {
            if (algorithm == keyExchangeAlgorithm) {
                return true;
            }
        }
        return false;
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

            context.setEncryptionAlgorithmClientToServer(
                    AlgorithmPicker.pickAlgorithm(
                                    context.getChooser()
                                            .getClientSupportedEncryptionAlgorithmsClientToServer(),
                                    context.getChooser()
                                            .getServerSupportedEncryptionAlgorithmsClientToServer())
                            .orElse(null));

            context.setEncryptionAlgorithmServerToClient(
                    AlgorithmPicker.pickAlgorithm(
                                    context.getChooser()
                                            .getClientSupportedEncryptionAlgorithmsServerToClient(),
                                    context.getChooser()
                                            .getServerSupportedEncryptionAlgorithmsServerToClient())
                            .orElse(null));

            context.setHostKeyAlgorithm(
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
    public KeyExchangeInitMessageParser getParser(byte[] array) {
        return new KeyExchangeInitMessageParser(array);
    }

    @Override
    public KeyExchangeInitMessageParser getParser(byte[] array, int startPosition) {
        return new KeyExchangeInitMessageParser(array, startPosition);
    }

    public static final KeyExchangeInitMessagePreparator PREPARATOR =
            new KeyExchangeInitMessagePreparator();

    public static final KeyExchangeInitMessageSerializer SERIALIZER =
            new KeyExchangeInitMessageSerializer();
}
