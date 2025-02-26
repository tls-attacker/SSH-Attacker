/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.constants;

import java.util.Collections;
import java.util.Map;
import java.util.TreeMap;

public enum LanguageTag {
    /*
     * Sources:
     * - https://www.iana.org/assignments/lang-tag-apps/lang-tag-apps.xhtml
     * - https://www.rfc-editor.org/rfc/rfc3066
     *
     * <p> rfc3066 was replaced by rfc4646. But the tags are still valid
     *
     * <p> LanguageTag are mostly not used by SSH servers, but they can.
     */
    // [ RFC 3066 ]
    ART_LOJBAN("art-lojban"),
    AZ_ARAB("az-Arab"),
    AZ_CYRL("az-Cyrl"),
    AZ_LATN("az-Latn"),
    BE_LATN("be-Latn"),
    BS_CYRL("bs-Cyrl"),
    BS_LATN("bs-Latn"),
    CEL_GAULISH("cel-gaulish"),
    DE_1901("de-1901"),
    DE_1996("de-1996"),
    DE_AT_1901("de-AT-1901"),
    DE_AT_1996("de-AT-1996"),
    DE_CH_1901("de-CH-1901"),
    DE_CH_1996("de-CH-1996"),
    DE_DE_1901("de-DE-1901"),
    DE_DE_1996("de-DE-1996"),
    EN_BOONT("en-boont"),
    EN_GB_OED("en-GB-oed"),
    EN_SCOUSE("en-scouse"),
    ES_419("es-419"),
    I_AMI("i-ami"),
    I_BNN("i-bnn"),
    I_DEFAULT("i-default"),
    I_ENOCHIAN("i-enochian"),
    I_HAK("i-hak"),
    I_KLINGON("i-klingon"),
    I_LUX("i-lux"),
    I_MINGO("i-mingo"),
    I_NAVAJO("i-navajo"),
    I_PWN("i-pwn"),
    I_TAO("i-tao"),
    I_TAY("i-tay"),
    I_TSU("i-tsu"),
    IU_CANS("iu-Cans"),
    IU_LATN("iu-Latn"),
    MN_CYRL("mn-Cyrl"),
    MN_MONG("mn-Mong"),
    NO_BOK("no-bok"),
    NO_NYN("no-nyn"),
    SGN_BE_FR("sgn-BE-fr"),
    SGN_BE_NL("sgn-BE-nl"),
    SGN_BR("sgn-BR"),
    SGN_CH_DE("sgn-CH-de"),
    SGN_CO("sgn-CO"),
    SGN_DE("sgn-DE"),
    SGN_DK("sgn-DK"),
    SGN_ES("sgn-ES"),
    SGN_FR("sgn-FR"),
    SGN_GB("sgn-GB"),
    SGN_GR("sgn-GR"),
    SGN_IE("sgn-IE"),
    SGN_IT("sgn-IT"),
    SGN_JP("sgn-JP"),
    SGN_MX("sgn-MX"),
    SGN_NL("sgn-NL"),
    SGN_NO("sgn-NO"),
    SGN_PT("sgn-PT"),
    SGN_SE("sgn-SE"),
    SGN_US("sgn-US"),
    SGN_ZA("sgn-ZA"),
    SL_ROZAJ("sl-rozaj"),
    SR_CYRL("sr-Cyrl"),
    SR_LATN("sr-Latn"),
    TG_ARAB("tg-Arab"),
    TG_CYRL("tg-Cyrl"),
    UZ_CYRL("uz-Cyrl"),
    UZ_LATN("uz-Latn"),
    YI_LATN("yi-latn"),
    ZH_CMN("zh-cmn"),
    ZH_CMN_HANS("zh-cmn-Hans"),
    ZH_CMN_HANT("zh-cmn-Hant"),
    ZH_GAN("zh-gan"),
    ZH_GUOYU("zh-guoyu"),
    ZH_HAKKA("zh-hakka"),
    ZH_HANS("zh-Hans"),
    ZH_HANS_CN("zh-Hans-CN"),
    ZH_HANS_HK("zh-Hans-HK"),
    ZH_HANS_MO("zh-Hans-MO"),
    ZH_HANS_SG("zh-Hans-SG"),
    ZH_HANS_TW("zh-Hans-TW"),
    ZH_HANT("zh-Hant"),
    ZH_HANT_CN("zh-Hant-CN"),
    ZH_HANT_HK("zh-Hant-HK"),
    ZH_HANT_MO("zh-Hant-MO"),
    ZH_HANT_SG("zh-Hant-SG"),
    ZH_HANT_TW("zh-Hant-TW"),
    ZH_MIN("zh-min"),
    ZH_MIN_NAN("zh-min-nan"),
    ZH_WUU("zh-wuu"),
    ZH_XIANG("zh-xiang"),
    ZH_YUE("zh-yue");

    private final String name;

    public static final Map<String, LanguageTag> map;

    static {
        Map<String, LanguageTag> mutableMap = new TreeMap<>();
        for (LanguageTag tag : values()) {
            if (tag.name != null) {
                mutableMap.put(tag.name, tag);
            }
        }
        map = Collections.unmodifiableMap(mutableMap);
    }

    LanguageTag(String name) {
        this.name = name;
    }

    @Override
    public String toString() {
        return name;
    }

    public String getName() {
        return name;
    }

    public static LanguageTag fromName(String name) {
        return map.get(name);
    }
}
