package de.rub.nds.sshattacker.state;

import de.rub.nds.sshattacker.config.Config;
import de.rub.nds.sshattacker.constants.CompressionAlgorithm;
import de.rub.nds.sshattacker.constants.EncryptionAlgorithm;
import de.rub.nds.sshattacker.constants.KeyExchangeAlgorithm;
import de.rub.nds.sshattacker.constants.Language;
import de.rub.nds.sshattacker.constants.MACAlgorithm;
import de.rub.nds.sshattacker.constants.PublicKeyAuthenticationAlgorithm;
import java.util.List;

public class Chooser {

    private SshContext context;
    private Config config;
    
    public Chooser(SshContext context, Config config){
        this.context = context;
        this.config = config;
    }
    public String getClientVersion() {
        if (context.getClientVersion() != null) {
            return context.getClientVersion();
        } else {
            return config.getClientVersion();
        }
    }

    public String getClientComment() {
        if (context.getClientComment() != null) {
            return context.getClientComment();
        } else {
            return config.getClientComment();
        }
    }

    public String getServerVersion() {
        if (context.getServerVersion() != null) {
            return context.getServerVersion();
        } else {
            return config.getServerVersion();
        }
    }

    public String getServerComment() {
        if (context.getServerComment() != null) {
            return context.getServerComment();
        } else {
            return config.getServerComment();
        }
    }

    public byte[] getClientCookie() {
        if (context.getClientCookie() != null) {
            return context.getClientCookie();
        } else {
            return config.getClientCookie();
        }
    }

    public byte[] getServerCookie() {
        if (context.getServerCookie() != null) {
            return context.getServerCookie();
        } else {
            return config.getServerCookie();
        }
    }

    public List<KeyExchangeAlgorithm> getClientSupportedKeyExchangeAlgorithms() {
        if (context.getClientSupportedKeyExchangeAlgorithms() != null) {
            return context.getClientSupportedKeyExchangeAlgorithms();
        } else {
            return config.getClientSupportedKeyExchangeAlgorithms();
        }
    }

    public List<KeyExchangeAlgorithm> getServerSupportedKeyExchangeAlgorithms() {
        if (context.getServerSupportedKeyExchangeAlgorithms() != null) {
            return context.getServerSupportedKeyExchangeAlgorithms();
        } else {
            return config.getServerSupportedKeyExchangeAlgorithms();
        }
    }

    public List<PublicKeyAuthenticationAlgorithm> getClientSupportedHostKeyAlgorithms() {
        if (context.getClientSupportedHostKeyAlgorithms() != null) {
            return context.getClientSupportedHostKeyAlgorithms();
        } else {
            return config.getClientSupportedHostKeyAlgorithms();
        }
    }

    public List<PublicKeyAuthenticationAlgorithm> getServerSupportedHostKeyAlgorithms() {
        if (context.getServerSupportedHostKeyAlgorithms() != null) {
            return context.getServerSupportedHostKeyAlgorithms();
        } else {
            return config.getServerSupportedHostKeyAlgorithms();
        }
    }

    public List<EncryptionAlgorithm> getClientSupportedCipherAlgorithmsSending() {
        if (context.getClientSupportedCipherAlgorithmsSending() != null) {
            return context.getClientSupportedCipherAlgorithmsSending();
        } else {
            return config.getClientSupportedCipherAlgorithmsSending();
        }
    }

    public List<EncryptionAlgorithm> getClientSupportedCipherAlgorithmsReceiving() {
        if (context.getClientSupportedCipherAlgorithmsReceiving() != null) {
            return context.getClientSupportedCipherAlgorithmsReceiving();
        } else {
            return config.getClientSupportedCipherAlgorithmsReceiving();
        }
    }

    public List<EncryptionAlgorithm> getServerSupportedCipherAlgorithmsSending() {
        if (context.getServerSupportedCipherAlgorithmsSending() != null) {
            return context.getServerSupportedCipherAlgorithmsSending();
        } else {
            return config.getServerSupportedCipherAlgorithmsSending();
        }
    }

    public List<EncryptionAlgorithm> getServerSupportedCipherAlgorithmsReceiving() {
        if (context.getServerSupportedCipherAlgorithmsReceiving() != null) {
            return context.getServerSupportedCipherAlgorithmsReceiving();
        } else {
            return config.getServerSupportedCipherAlgorithmsReceiving();
        }
    }

    public List<MACAlgorithm> getClientSupportedMacAlgorithmsSending() {
        if (context.getClientSupportedMacAlgorithmsSending() != null) {
            return context.getClientSupportedMacAlgorithmsSending();
        } else {
            return config.getClientSupportedMacAlgorithmsSending();
        }
    }

    public List<MACAlgorithm> getClientSupportedMacAlgorithmsReceiving() {
        if (context.getClientSupportedMacAlgorithmsReceiving() != null) {
            return context.getClientSupportedMacAlgorithmsReceiving();
        } else {
            return config.getClientSupportedMacAlgorithmsReceiving();
        }
    }

    public List<MACAlgorithm> getServerSupportedMacAlgorithmsSending() {
        if (context.getServerSupportedMacAlgorithmsSending() != null) {
            return context.getServerSupportedMacAlgorithmsSending();
        } else {
            return config.getServerSupportedMacAlgorithmsSending();
        }
    }

    public List<MACAlgorithm> getServerSupportedMacAlgorithmsReceiving() {
        if (context.getServerSupportedMacAlgorithmsReceiving() != null) {
            return context.getServerSupportedMacAlgorithmsReceiving();
        } else {
            return config.getServerSupportedMacAlgorithmsReceiving();
        }
    }

    public List<CompressionAlgorithm> getClientSupportedCompressionAlgorithmsSending() {
        if (context.getClientSupportedCompressionAlgorithmsSending() != null) {
            return context.getClientSupportedCompressionAlgorithmsSending();
        } else {
            return config.getClientSupportedCompressionAlgorithmsSending();
        }
    }

    public List<CompressionAlgorithm> getClientSupportedCompressionAlgorithmsReceiving() {
        if (context.getClientSupportedCompressionAlgorithmsReceiving() != null) {
            return context.getClientSupportedCompressionAlgorithmsReceiving();
        } else {
            return config.getClientSupportedCompressionAlgorithmsReceiving();
        }
    }

    public List<CompressionAlgorithm> getServerSupportedCompressionAlgorithmsSending() {
        if (context.getServerSupportedCompressionAlgorithmsSending() != null) {
            return context.getServerSupportedCompressionAlgorithmsSending();
        } else {
            return config.getServerSupportedCompressionAlgorithmsSending();
        }
    }

    public List<CompressionAlgorithm> getServerSupportedCompressionAlgorithmsReceiving() {
        if (context.getServerSupportedCompressionAlgorithmsReceiving() != null) {
            return context.getServerSupportedCompressionAlgorithmsReceiving();
        } else {
            return config.getServerSupportedCompressionAlgorithmsReceiving();
        }
    }

    public List<Language> getClientSupportedLanguagesSending() {
        if (context.getClientSupportedLanguagesSending() != null) {
            return context.getClientSupportedLanguagesSending();
        } else {
            return config.getClientSupportedLanguagesSending();
        }
    }

    public List<Language> getClientSupportedLanguagesReceiving() {
        if (context.getClientSupportedLanguagesReceiving() != null) {
            return context.getClientSupportedLanguagesReceiving();
        } else {
            return config.getClientSupportedLanguagesReceiving();
        }
    }

    public List<Language> getServerSupportedLanguagesSending() {
        if (context.getServerSupportedLanguagesSending() != null) {
            return context.getServerSupportedLanguagesSending();
        } else {
            return config.getServerSupportedLanguagesSending();
        }
    }

    public List<Language> getServerSupportedLanguagesReceiving() {
        if (context.getServerSupportedLanguagesReceiving() != null) {
            return context.getServerSupportedLanguagesReceiving();
        } else {
            return config.getServerSupportedLanguagesReceiving();
        }
    }

    public byte getClientFirstKeyExchangePacketFollows() {
        if (context.getClientFirstKeyExchangePacketFollows() != null) {
            return context.getClientFirstKeyExchangePacketFollows();
        } else {
            return config.getClientFirstKeyExchangePacketFollows();
        }
    }

    public byte getServerFirstKeyExchangePacketFollows() {
        if (context.getServerFirstKeyExchangePacketFollows() != null) {
            return context.getServerFirstKeyExchangePacketFollows();
        } else {
            return config.getServerFirstKeyExchangePacketFollows();
        }
    }

    public int getClientReserved() {
        if (context.getClientReserved() != null) {
            return context.getClientReserved();
        } else {
            return config.getClientReserved();
        }
    }

    public int getServerReserved() {
        if (context.getServerReserved() != null) {
            return context.getServerReserved();
        } else {
            return config.getServerReserved();
        }
    }
}
