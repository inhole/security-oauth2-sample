package com.securityoauth2sample.config;

import io.jsonwebtoken.security.Keys;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.util.Base64;

@ConfigurationProperties(prefix = "jwt")
@Getter
@Setter
public class AppConfig {

    private SecretKey key;
    private int accessExpTime;
    private int refreshExpTime;
    private String jwtHeader;
    private String jwtType;

    public void setKey(String key) {
        // 암호화 키 디코딩
        this.key = Keys.hmacShaKeyFor(Base64.getDecoder().decode(key));
    }

    public SecretKey getKey() {
        return key;
    }



}
