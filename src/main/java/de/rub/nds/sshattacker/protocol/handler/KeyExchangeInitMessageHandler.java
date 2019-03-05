package de.rub.nds.sshattacker.protocol.handler;

import de.rub.nds.sshattacker.constants.EncryptionAlgorithm;
import de.rub.nds.sshattacker.constants.CompressionAlgorithm;
import de.rub.nds.sshattacker.constants.KeyExchangeAlgorithm;
import de.rub.nds.sshattacker.constants.Language;
import de.rub.nds.sshattacker.constants.MACAlgorithm;
import de.rub.nds.sshattacker.constants.MessageIDConstants;
import de.rub.nds.sshattacker.constants.PublicKeyAuthenticationAlgorithm;
import de.rub.nds.sshattacker.protocol.AlgorithmPicker;
import de.rub.nds.sshattacker.protocol.message.KeyExchangeInitMessage;
import de.rub.nds.sshattacker.protocol.serializer.KeyExchangeInitMessageSerializer;
import de.rub.nds.sshattacker.state.SshContext;
import de.rub.nds.sshattacker.util.Converter;

public class KeyExchangeInitMessageHandler extends Handler<KeyExchangeInitMessage> {

    public KeyExchangeInitMessageHandler(SshContext context, KeyExchangeInitMessage message) {
        super(context, message);
    }

    @Override
    public void handle() {
        // TODO currently only handling for server messages
        context.setServerCookie(message.getCookie().getValue());
        context.setServerSupportedKeyExchangeAlgorithms(Converter.StringToAlgorithms(message.getKeyExchangeAlgorithms().getValue(), KeyExchangeAlgorithm.class));
        context.setServerSupportedHostKeyAlgorithms(Converter.StringToAlgorithms(message.getServerHostKeyAlgorithms().getValue(), PublicKeyAuthenticationAlgorithm.class));
        context.setServerSupportedCipherAlgorithmsClientToServer(Converter.StringToAlgorithms(message.getEncryptionAlgorithmsClientToServer().getValue(), EncryptionAlgorithm.class));
        context.setServerSupportedCipherAlgorithmsServerToClient(Converter.StringToAlgorithms(message.getEncryptionAlgorithmsServerToClient().getValue(), EncryptionAlgorithm.class));
        context.setServerSupportedMacAlgorithmsClientToServer(Converter.StringToAlgorithms(message.getMacAlgorithmsClientToServer().getValue(), MACAlgorithm.class));
        context.setServerSupportedMacAlgorithmsServerToClient(Converter.StringToAlgorithms(message.getMacAlgorithmsServerToClient().getValue(), MACAlgorithm.class));
        context.setServerSupportedCompressionAlgorithmsClientToServer(Converter.StringToAlgorithms(message.getCompressionAlgorithmsClientToServer().getValue(), CompressionAlgorithm.class));
        context.setServerSupportedCompressionAlgorithmsServerToClient(Converter.StringToAlgorithms(message.getCompressionAlgorithmsServerToClient().getValue(), CompressionAlgorithm.class));
        context.setServerSupportedLanguagesClientToServer(Converter.StringToAlgorithms(message.getLanguagesClientToServer().getValue(), Language.class));
        context.setServerSupportedLanguagesServerToClient(Converter.StringToAlgorithms(message.getLanguagesServerToClient().getValue(), Language.class));
        context.setServerReserved(message.getReserved().getValue());
        
        adjustAlgorithms();
        
        context.appendToExchangeHashInput(Converter.concatenate(new byte[] {MessageIDConstants.SSH_MSG_KEXINIT},
                new KeyExchangeInitMessageSerializer(message).serializeMessageSpecificPayload()));
        
        
    }
    
        private void adjustAlgorithms() {
        context.setKeyExchangeAlgorithm(
                AlgorithmPicker.pickAlgorithm(
                        context.getClientSupportedKeyExchangeAlgorithms(),
                        context.getServerSupportedKeyExchangeAlgorithms()).get());

        context.setCipherAlgorithmClientToServer(
                AlgorithmPicker.pickAlgorithm(
                        context.getClientSupportedCipherAlgorithmsClientToServer(),
                        context.getServerSupportedCipherAlgorithmsClientToServer()).get());

        context.setCipherAlgorithmServerToClient(
                AlgorithmPicker.pickAlgorithm(
                        context.getClientSupportedCipherAlgorithmsServerToClient(),
                        context.getServerSupportedCipherAlgorithmsServerToClient()).get());

        context.setServerHostKeyAlgorithm(
                AlgorithmPicker.pickAlgorithm(context.getClientSupportedHostKeyAlgorithms(),
                        context.getServerSupportedHostKeyAlgorithms()).get());
        
        context.setMacAlgorithmClientToServer(
                AlgorithmPicker.pickAlgorithm(
                context.getClientSupportedMacAlgorithmsClientToServer(),
                context.getServerSupportedMacAlgorithmsClientToServer()).get());
        
        context.setMacAlgorithmServerToClient(
                AlgorithmPicker.pickAlgorithm(
                context.getClientSupportedMacAlgorithmsServerToClient(),
                context.getServerSupportedMacAlgorithmsServerToClient()).get());

        context.setCompressionAlgorithmClientToServer(
                AlgorithmPicker.pickAlgorithm(
                context.getClientSupportedCompressionAlgorithmsClientToServer(),
                        context.getServerSupportedCompressionAlgorithmsClientToServer()).get());
        
        context.setCompressionAlgorithmServerToClient(
                AlgorithmPicker.pickAlgorithm(
                context.getClientSupportedCompressionAlgorithmsServerToClient(),
                context.getServerSupportedCompressionAlgorithmsServerToClient()).get());
        
        context.setLanguageClientToServer(
                AlgorithmPicker.pickAlgorithm(
                        context.getClientSupportedLanguagesClientToServer(),
                        context.getServerSupportedLanguagesServerToClient()).get());
        
        context.setLanguageServerToClient(
                AlgorithmPicker.pickAlgorithm(
                        context.getClientSupportedLanguagesServerToClient(),
                        context.getServerSupportedLanguagesServerToClient()).get());
    }
}
