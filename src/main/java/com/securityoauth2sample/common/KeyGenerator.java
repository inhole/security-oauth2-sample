package com.securityoauth2sample.common;

import java.util.UUID;

public final class KeyGenerator {

    /**
     * 랜덤 key 생성
     * @return
     */
    public static String generateKey() {
        return UUID.randomUUID().toString().replace("-", "");
    }
}
