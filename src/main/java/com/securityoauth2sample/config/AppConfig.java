package com.securityoauth2sample.config;

import io.jsonwebtoken.security.Keys;
import org.springframework.boot.context.properties.ConfigurationProperties;

import javax.crypto.SecretKey;
import java.util.Base64;

@ConfigurationProperties(prefix = "jwt")
public class AppConfig {

    private SecretKey key;

    public void setKey(String key) {
        // 암호화 키 디코딩
        this.key = Keys.hmacShaKeyFor(Base64.getDecoder().decode(key));
    }

    public SecretKey getKey() {
        return key;
    }

}
