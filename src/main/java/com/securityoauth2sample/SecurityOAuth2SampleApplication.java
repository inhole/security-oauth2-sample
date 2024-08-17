package com.securityoauth2sample;

import com.securityoauth2sample.config.JwtProperties;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;

@EnableConfigurationProperties(JwtProperties.class)
@SpringBootApplication
public class SecurityOAuth2SampleApplication {

    public static void main(String[] args) {
        SpringApplication.run(SecurityOAuth2SampleApplication.class, args);
    }

}
