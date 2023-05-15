# Implemented Messages

## Transport Layer Protocol (RFC 4253)

|       Message Type        | Message ID |   XML Tag / Java Class   |     Message      |    Preparator    |    Serializer    |      Parser      |     Handler      |
|---------------------------|:----------:|--------------------------|:----------------:|:----------------:|:----------------:|:----------------:|:----------------:|
| Version Exchange          |     -      | `VersionExchangeMessage` | &#x2714;&#xfe0f; | &#x2714;&#xfe0f; | &#x2714;&#xfe0f; | &#x2714;&#xfe0f; | &#x2714;&#xfe0f; |
| `SSH_MSG_DISCONNECT`      |     1      | `DisconnectMessage`      | &#x2714;&#xfe0f; | &#x26a0;&#xfe0f; | &#x2714;&#xfe0f; | &#x2714;&#xfe0f; | &#x2714;&#xfe0f; |
| `SSH_MSG_IGNORE`          |     2      | `IgnoreMessage`          | &#x2714;&#xfe0f; | &#x26a0;&#xfe0f; | &#x2714;&#xfe0f; | &#x2714;&#xfe0f; | &#x2714;&#xfe0f; |
| `SSH_MSG_UNIMPLEMENTED`   |     3      | `UnimplementedMessage`   | &#x2714;&#xfe0f; | &#x26a0;&#xfe0f; | &#x2714;&#xfe0f; | &#x2714;&#xfe0f; |     &#x274c;     |
| `SSH_MSG_DEBUG`           |     4      | `DebugMessage`           | &#x2714;&#xfe0f; | &#x26a0;&#xfe0f; | &#x2714;&#xfe0f; | &#x2714;&#xfe0f; | &#x2714;&#xfe0f; |
| `SSH_MSG_SERVICE_REQUEST` |     5      | `ServiceRequestMessage`  | &#x2714;&#xfe0f; | &#x2714;&#xfe0f; | &#x2714;&#xfe0f; | &#x2714;&#xfe0f; |     &#x274c;     |
| `SSH_MSG_SERVICE_ACCEPT`  |     6      | `ServiceAcceptMessage`   | &#x2714;&#xfe0f; | &#x26a0;&#xfe0f; | &#x2714;&#xfe0f; | &#x2714;&#xfe0f; | &#x26a0;&#xfe0f; |
| `SSH_MSG_KEXINIT`         |     20     | `KeyExchangeInitMessage` | &#x2714;&#xfe0f; | &#x2714;&#xfe0f; | &#x2714;&#xfe0f; | &#x2714;&#xfe0f; | &#x2714;&#xfe0f; |
| `SSH_MSG_NEWKEYS`         |     21     | `NewKeysMessage`         | &#x2714;&#xfe0f; | &#x2714;&#xfe0f; | &#x2714;&#xfe0f; | &#x2714;&#xfe0f; | &#x26a0;&#xfe0f; |

### Key Exchange: Diffie Hellman Group Exchange (RFC 4419)

|           Message Type           | Message ID |        XML Tag / Java Class         |     Message      |    Preparator    |    Serializer    |      Parser      |     Handler      |
|----------------------------------|:----------:|-------------------------------------|:----------------:|:----------------:|:----------------:|:----------------:|:----------------:|
| `SSH_MSG_KEX_DH_GEX_REQUEST_OLD` |     30     | `DhGexKeyExchangeOldRequestMessage` | &#x2714;&#xfe0f; | &#x2714;&#xfe0f; | &#x2714;&#xfe0f; |     &#x274c;     |     &#x274c;     |
| `SSH_MSG_KEX_DH_GEX_REQUEST`     |     34     | `DhGexKeyExchangeRequestMessage`    | &#x2714;&#xfe0f; | &#x2714;&#xfe0f; | &#x2714;&#xfe0f; |     &#x274c;     |     &#x274c;     |
| `SSH_MSG_KEX_DH_GEX_GROUP`       |     31     | `DhGexKeyExchangeGroupMessage`      | &#x2714;&#xfe0f; |     &#x274c;     |     &#x274c;     | &#x2714;&#xfe0f; | &#x2714;&#xfe0f; |
| `SSH_MSG_KEX_DH_GEX_INIT`        |     32     | `DhGexKeyExchangeInitMessage`       | &#x2714;&#xfe0f; | &#x2714;&#xfe0f; | &#x2714;&#xfe0f; |     &#x274c;     |     &#x274c;     |
| `SSH_MSG_KEX_DH_GEX_REPLY`       |     33     | `DhGexKeyExchangeReplyMessage`      | &#x2714;&#xfe0f; |     &#x274c;     |     &#x274c;     | &#x2714;&#xfe0f; | &#x2714;&#xfe0f; |

### Key Exchange: Diffie-Hellman Named Groups (RFC 4253)

|     Message Type      | Message ID |    XML Tag / Java Class     |     Message      |    Preparator    |    Serializer    |      Parser      |     Handler      |
|-----------------------|:----------:|-----------------------------|:----------------:|:----------------:|:----------------:|:----------------:|:----------------:|
| `SSH_MSG_KEXDH_INIT`  |     30     | `DhKeyExchangeInitMessage`  | &#x2714;&#xfe0f; | &#x2714;&#xfe0f; | &#x2714;&#xfe0f; |     &#x274c;     |     &#x274c;     |
| `SSH_MSG_KEXDH_REPLY` |     31     | `DhKeyExchangeReplyMessage` | &#x2714;&#xfe0f; |     &#x274c;     |     &#x274c;     | &#x2714;&#xfe0f; | &#x2714;&#xfe0f; |

### Key Exchange: ECDH (RFC 5656)

|       Message Type       | Message ID |     XML Tag / Java Class      |     Message      |    Preparator    |    Serializer    |      Parser      |     Handler      |
|--------------------------|:----------:|-------------------------------|:----------------:|:----------------:|:----------------:|:----------------:|:----------------:|
| `SSH_MSG_KEX_ECDH_INIT`  |     30     | `EcdhKeyExchangeInitMessage`  | &#x2714;&#xfe0f; | &#x2714;&#xfe0f; | &#x2714;&#xfe0f; | &#x2714;&#xfe0f; |     &#x274c;     |
| `SSH_MSG_KEX_ECDH_REPLY` |     31     | `EcdhKeyExchangeReplyMessage` | &#x2714;&#xfe0f; | &#x26a0;&#xfe0f; | &#x2714;&#xfe0f; | &#x2714;&#xfe0f; | &#x2714;&#xfe0f; |

### Key Exchange: ECMQV (RFC 5656)

|     Message Type      | Message ID | XML Tag / Java Class | Message  | Preparator | Serializer |  Parser  | Handler  |
|-----------------------|:----------:|----------------------|:--------:|:----------:|:----------:|:--------:|:--------:|
| `SSH_MSG_ECMQV_INIT`  |     30     | -                    | &#x274c; |  &#x274c;  |  &#x274c;  | &#x274c; | &#x274c; |
| `SSH_MSG_ECMQV_REPLY` |     31     | -                    | &#x274c; |  &#x274c;  |  &#x274c;  | &#x274c; | &#x274c; |

### Key Exchange: RSA (RFC 4432)

|      Message Type       | Message ID | XML Tag / Java Class | Message  | Preparator | Serializer |  Parser  | Handler  |
|-------------------------|:----------:|----------------------|:--------:|:----------:|:----------:|:--------:|:--------:|
| `SSH_MSG_KEXRSA_PUBKEY` |     30     | -                    | &#x274c; |  &#x274c;  |  &#x274c;  | &#x274c; | &#x274c; |
| `SSH_MSG_KEXRSA_SECRET` |     31     | -                    | &#x274c; |  &#x274c;  |  &#x274c;  | &#x274c; | &#x274c; |
| `SSH_MSG_KEXRSA_DONE`   |     32     | -                    | &#x274c; |  &#x274c;  |  &#x274c;  | &#x274c; | &#x274c; |

### Key Exchange: GSS-API (RFC 4462)

|       Message Type        | Message ID | XML Tag / Java Class | Message  | Preparator | Serializer |  Parser  | Handler  |
|---------------------------|:----------:|----------------------|:--------:|:----------:|:----------:|:--------:|:--------:|
| `SSH_MSG_KEXGSS_INIT`     |     30     | -                    | &#x274c; |  &#x274c;  |  &#x274c;  | &#x274c; | &#x274c; |
| `SSH_MSG_KEXGSS_CONTINUE` |     31     | -                    | &#x274c; |  &#x274c;  |  &#x274c;  | &#x274c; | &#x274c; |
| `SSH_MSG_KEXGSS_COMPLETE` |     32     | -                    | &#x274c; |  &#x274c;  |  &#x274c;  | &#x274c; | &#x274c; |
| `SSH_MSG_KEXGSS_HOSTKEY`  |     33     | -                    | &#x274c; |  &#x274c;  |  &#x274c;  | &#x274c; | &#x274c; |
| `SSH_MSG_KEXGSS_ERROR`    |     34     | -                    | &#x274c; |  &#x274c;  |  &#x274c;  | &#x274c; | &#x274c; |
| `SSH_MSG_KEXGSS_GROUPREQ` |     40     | -                    | &#x274c; |  &#x274c;  |  &#x274c;  | &#x274c; | &#x274c; |
| `SSH_MSG_KEXGSS_GROUP`    |     41     | -                    | &#x274c; |  &#x274c;  |  &#x274c;  | &#x274c; | &#x274c; |

---

## Authentication Protocol (RFC 4252)

|        Message Type        | Message ID |   XML Tag / Java Class    |     Message      |    Preparator    |    Serializer    |      Parser      | Handler  |
|----------------------------|:----------:|---------------------------|:----------------:|:----------------:|:----------------:|:----------------:|:--------:|
| `SSH_MSG_USERAUTH_REQUEST` |     50     | `UserAuthPasswordMessage` | &#x26a0;&#xfe0f; | &#x26a0;&#xfe0f; | &#x26a0;&#xfe0f; |     &#x274c;     | &#x274c; |
| `SSH_MSG_USERAUTH_FAILURE` |     51     | `UserAuthFailureMessage`  | &#x2714;&#xfe0f; | &#x26a0;&#xfe0f; | &#x2714;&#xfe0f; | &#x2714;&#xfe0f; | &#x274c; |
| `SSH_MSG_USERAUTH_SUCCESS` |     52     | `UserAuthSuccessMessage`  | &#x2714;&#xfe0f; | &#x2714;&#xfe0f; | &#x2714;&#xfe0f; | &#x2714;&#xfe0f; | &#x274c; |
| `SSH_MSG_USERAUTH_BANNER`  |     53     | `UserAuthBannerMessage`   | &#x2714;&#xfe0f; | &#x26a0;&#xfe0f; | &#x2714;&#xfe0f; | &#x2714;&#xfe0f; | &#x274c; |

### Authentication Method: publickey (RFC 4252)

|       Message Type       | Message ID | XML Tag / Java Class | Message  | Preparator | Serializer |  Parser  | Handler  |
|--------------------------|:----------:|----------------------|:--------:|:----------:|:----------:|:--------:|:--------:|
| `SSH_MSG_USERAUTH_PK_OK` |     60     | -                    | &#x274c; |  &#x274c;  |  &#x274c;  | &#x274c; | &#x274c; |

### Authentication Method: password (RFC 4252)

|            Message Type             | Message ID | XML Tag / Java Class | Message  | Preparator | Serializer |  Parser  | Handler  |
|-------------------------------------|:----------:|----------------------|:--------:|:----------:|:----------:|:--------:|:--------:|
| `SSH_MSG_USERAUTH_PASSWD_CHANGEREQ` |     60     | -                    | &#x274c; |  &#x274c;  |  &#x274c;  | &#x274c; | &#x274c; |

### Authentication Method: keyboard-interactive (RFC 4256)

|           Message Type           | Message ID | XML Tag / Java Class | Message  | Preparator | Serializer |  Parser  | Handler  |
|----------------------------------|:----------:|----------------------|:--------:|:----------:|:----------:|:--------:|:--------:|
| `SSH_MSG_USERAUTH_INFO_REQUEST`  |     60     | -                    | &#x274c; |  &#x274c;  |  &#x274c;  | &#x274c; | &#x274c; |
| `SSH_MSG_USERAUTH_INFO_RESPONSE` |     61     | -                    | &#x274c; |  &#x274c;  |  &#x274c;  | &#x274c; | &#x274c; |

### Authentication Method: GSS-API (RFC 4462)

|                Message Type                 | Message ID | XML Tag / Java Class | Message  | Preparator | Serializer |  Parser  | Handler  |
|---------------------------------------------|:----------:|----------------------|:--------:|:----------:|:----------:|:--------:|:--------:|
| `SSH_MSG_USERAUTH_GSSAPI_RESPONSE`          |     60     | -                    | &#x274c; |  &#x274c;  |  &#x274c;  | &#x274c; | &#x274c; |
| `SSH_MSG_USERAUTH_GSSAPI_TOKEN`             |     61     | -                    | &#x274c; |  &#x274c;  |  &#x274c;  | &#x274c; | &#x274c; |
| `SSH_MSG_USERAUTH_GSSAPI_EXCHANGE_COMPLETE` |     63     | -                    | &#x274c; |  &#x274c;  |  &#x274c;  | &#x274c; | &#x274c; |
| `SSH_MSG_USERAUTH_GSSAPI_ERROR`             |     64     | -                    | &#x274c; |  &#x274c;  |  &#x274c;  | &#x274c; | &#x274c; |
| `SSH_MSG_USERAUTH_GSSAPI_ERRTOK`            |     65     | -                    | &#x274c; |  &#x274c;  |  &#x274c;  | &#x274c; | &#x274c; |
| `SSH_MSG_USERAUTH_GSSAPI_MIC`               |     66     | -                    | &#x274c; |  &#x274c;  |  &#x274c;  | &#x274c; | &#x274c; |

---

## Connection Protocol (RFC 4254)

|            Message Type             | Message ID |       XML Tag / Java Class       |     Message      |    Preparator    |    Serializer    |      Parser      |     Handler      |
|-------------------------------------|:----------:|----------------------------------|:----------------:|:----------------:|:----------------:|:----------------:|:----------------:|
| `SSH_MSG_GLOBAL_REQUEST`            |     80     | `GlobalRequestMessage`           | &#x2714;&#xfe0f; | &#x26a0;&#xfe0f; | &#x2714;&#xfe0f; | &#x2714;&#xfe0f; |     &#x274c;     |
| `SSH_MSG_REQUEST_SUCCESS`           |     81     | `RequestSuccessMessage`          | &#x26a0;&#xfe0f; | &#x26a0;&#xfe0f; | &#x26a0;&#xfe0f; | &#x26a0;&#xfe0f; |     &#x274c;     |
| `SSH_MSG_REQUEST_FAILURE`           |     82     | `RequestFailureMessage`          | &#x2714;&#xfe0f; | &#x2714;&#xfe0f; | &#x2714;&#xfe0f; | &#x2714;&#xfe0f; |     &#x274c;     |
| `SSH_MSG_CHANNEL_OPEN`              |     90     | `ChannelOpenMessage`             | &#x26a0;&#xfe0f; | &#x26a0;&#xfe0f; | &#x26a0;&#xfe0f; | &#x26a0;&#xfe0f; |     &#x274c;     |
| `SSH_MSG_CHANNEL_OPEN_CONFIRMATION` |     91     | `ChannelOpenConfirmationMessage` | &#x26a0;&#xfe0f; | &#x26a0;&#xfe0f; | &#x26a0;&#xfe0f; | &#x26a0;&#xfe0f; | &#x26a0;&#xfe0f; |
| `SSH_MSG_CHANNEL_OPEN_FAILURE`      |     92     | `ChannelOpenFailureMessage`      | &#x2714;&#xfe0f; | &#x26a0;&#xfe0f; | &#x2714;&#xfe0f; | &#x2714;&#xfe0f; |     &#x274c;     |
| `SSH_MSG_CHANNEL_WINDOW_ADJUST`     |     93     | `ChannelWindowAdjustMessage`     | &#x2714;&#xfe0f; | &#x26a0;&#xfe0f; | &#x2714;&#xfe0f; | &#x2714;&#xfe0f; |     &#x274c;     |
| `SSH_MSG_CHANNEL_DATA`              |     94     | `ChannelDataMessage`             | &#x2714;&#xfe0f; | &#x26a0;&#xfe0f; | &#x2714;&#xfe0f; | &#x2714;&#xfe0f; |     &#x274c;     |
| `SSH_MSG_CHANNEL_EXTENDED_DATA`     |     95     | `ChannelExtendedDataMessage`     | &#x2714;&#xfe0f; | &#x26a0;&#xfe0f; | &#x2714;&#xfe0f; | &#x2714;&#xfe0f; |     &#x274c;     |
| `SSH_MSG_CHANNEL_EOF`               |     96     | `ChannelEofMessage`              | &#x2714;&#xfe0f; | &#x26a0;&#xfe0f; | &#x2714;&#xfe0f; | &#x2714;&#xfe0f; |     &#x274c;     |
| `SSH_MSG_CHANNEL_CLOSE`             |     97     | `ChannelCloseMessage`            | &#x2714;&#xfe0f; | &#x26a0;&#xfe0f; | &#x2714;&#xfe0f; | &#x2714;&#xfe0f; |     &#x274c;     |
| `SSH_MSG_CHANNEL_REQUEST`           |     98     | `ChannelRequestMessage`          | &#x26a0;&#xfe0f; | &#x26a0;&#xfe0f; | &#x26a0;&#xfe0f; | &#x26a0;&#xfe0f; |     &#x274c;     |
| `SSH_MSG_CHANNEL_SUCCESS`           |     99     | `ChannelSuccessMessage`          | &#x2714;&#xfe0f; | &#x2714;&#xfe0f; | &#x2714;&#xfe0f; | &#x2714;&#xfe0f; |     &#x274c;     |
| `SSH_MSG_CHANNEL_FAILURE`           |    100     | `ChannelFailureMessage`          | &#x2714;&#xfe0f; | &#x2714;&#xfe0f; | &#x2714;&#xfe0f; | &#x2714;&#xfe0f; |     &#x274c;     |

