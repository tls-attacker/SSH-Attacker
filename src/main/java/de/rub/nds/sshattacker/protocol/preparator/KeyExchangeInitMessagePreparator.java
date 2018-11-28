package de.rub.nds.sshattacker.protocol.preparator;

import de.rub.nds.sshattacker.protocol.message.KeyExchangeInitMessage;
import de.rub.nds.sshattacker.state.SshContext;
import de.rub.nds.sshattacker.util.Converter;

public class KeyExchangeInitMessagePreparator extends Preparator<KeyExchangeInitMessage> {

    public KeyExchangeInitMessagePreparator(SshContext context, KeyExchangeInitMessage message) {
        super(context, message);
    }

    @Override
    public void prepare() {
        //TODO for now we only support using the same algorithms in both directions
        // adapt context to hold for client/server {algorithm for direction to and from client}
        message.setCookie(context.getClientCookie());
        message.setKeyExchangeAlgorithms(Converter.listofAlgorithmstoString(context.getClientSupportedKeyExchangeAlgorithms()));
        message.setKeyExchangeAlgorithmsLength(message.getKeyExchangeAlgorithms().getValue().length());
        message.setServerHostKeyAlgorithms(Converter.listofAlgorithmstoString(context.getClientSupportedHostKeyAlgorithms()));
        message.setServerHostKeyAlgorithmsLength(message.getServerHostKeyAlgorithms().getValue().length());
        message.setEncryptionAlgorithmsClientToServer(Converter.listofAlgorithmstoString(context.getClientSupportedCipherAlgorithms()));
        message.setEncryptionAlgorithmsClientToServerLength(message.getEncryptionAlgorithmsClientToServer().getValue().length());
        message.setEncryptionAlgorithmsServerToClient(Converter.listofAlgorithmstoString(context.getClientSupportedCipherAlgorithms()));
        message.setEncryptionAlgorithmsServerToClientLength(message.getEncryptionAlgorithmsServerToClient().getValue().length());
        message.setMacAlgorithmsClientToServer(Converter.listofAlgorithmstoString(context.getClientSupportedMacAlgorithms()));
        message.setMacAlgorithmsClientToServerLength(message.getMacAlgorithmsClientToServer().getValue().length());
        message.setMacAlgorithmsServerToClient(Converter.listofAlgorithmstoString(context.getClientSupportedMacAlgorithms()));
        message.setMacAlgorithmsServerToClientLength(message.getMacAlgorithmsServerToClient().getValue().length());
        message.setCompressionAlgorithmsClientToServer(Converter.listofAlgorithmstoString(context.getClientSupportedCompressionAlgorithms()));
        message.setCompressionAlgorithmsClientToServerLength(message.getCompressionAlgorithmsClientToServer().getValue().length());
        message.setCompressionAlgorithmsServerToClient(Converter.listofAlgorithmstoString(context.getClientSupportedCompressionAlgorithms()));
        message.setCompressionAlgorithmsServerToClientLength(message.getCompressionAlgorithmsServerToClient().getValue().length());
        message.setLanguagesClientToServer(Converter.listofAlgorithmstoString(context.getClientSupportedLanguages()));
        message.setLanguagesClientToServerLength(message.getCompressionAlgorithmsClientToServer().getValue().length());
        message.setLanguagesServerToClient(Converter.listofAlgorithmstoString(context.getClientSupportedLanguages()));
        message.setLanguagesServerToClientLength(message.getLanguagesServerToClient().getValue().length());
        message.setFirstKeyExchangePacketFollows(context.getFirstKeyExchangePacketFollows());
        message.setReserved(context.getReserved());
    }
}
