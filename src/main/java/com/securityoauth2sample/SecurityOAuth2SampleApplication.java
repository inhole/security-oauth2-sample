package com.securityoauth2sample;

import com.securityoauth2sample.config.properties.JwtProperties;
import com.securityoauth2sample.config.properties.RedisProperties;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;

@EnableConfigurationProperties({JwtProperties.class, RedisProperties.class})
@SpringBootApplication
public class SecurityOAuth2SampleApplication {

    public static void main(String[] args) {
        SpringApplication.run(SecurityOAuth2SampleApplication.class, args);
    }

}
