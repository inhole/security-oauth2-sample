package com.securityoauth2sample.config.properties;

import io.jsonwebtoken.security.Keys;
import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;

import javax.crypto.SecretKey;
import java.util.Base64;

@ConfigurationProperties(prefix = "spring.data.redis")
@Getter
@Setter
public class RedisProperties {

    private String host;
    private int port;

}
