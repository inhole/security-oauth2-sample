package com.securityoauth2sample.config.properties;

import io.jsonwebtoken.security.Keys;
import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;

import javax.crypto.SecretKey;
import java.util.Base64;

@ConfigurationProperties(prefix = "jwt")
@Getter
@Setter
public class JwtProperties {

    private SecretKey key;
    private int accessExpTime;
    private int refreshExpTime;
    private String jwtHeader;
    private String jwtType;
    private String keyRole;

    public void setKey(String key) {
        // 암호화 키 디코딩
        this.key = Keys.hmacShaKeyFor(Base64.getDecoder().decode(key));
    }

    public SecretKey getKey() {
        return key;
    }



}
