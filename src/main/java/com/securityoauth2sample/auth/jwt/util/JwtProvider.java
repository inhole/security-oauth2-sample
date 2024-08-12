package com.securityoauth2sample.auth.jwt.util;

import com.securityoauth2sample.config.AppConfig;
import com.securityoauth2sample.exception.Unauthorized;
import io.jsonwebtoken.*;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.util.Base64;
import java.util.Date;

@Slf4j
@RequiredArgsConstructor
@Component
public class JwtProvider {

    private final AppConfig appConfig;
    private SecretKey secretKey;

    public String generateKey() {
        // 암호화 키 생성
        SecretKey key2 = Jwts.SIG.HS256.key().build();
        byte[] encodedKey = key2.getEncoded();
        String strKey = Base64.getEncoder().encodeToString(encodedKey);
        log.info("strKey :: {}", strKey);
        return strKey;
    }

    /**
     * Token 생성
     * @param authentication
     * @return
     */
    public String generateAccessToken(Authentication authentication) {

        return Jwts.builder()
                .subject(authentication.getName())
                .signWith(appConfig.getKey())
                .issuedAt(new Date()) // 생성 일
                .expiration(new Date(System.currentTimeMillis() + 1000 * 60 * 60)) // 유효 기간 1시간
                .compact();
    }

    /**
     * Claims 추출/검증
     * @param jws
     * @return
     */
    private Claims parseClaims(String jws) {
        try {
            Jws<Claims> claims =  Jwts.parser()
                    .verifyWith(appConfig.getKey())
                    .build()
                    .parseSignedClaims(jws);
            return claims.getPayload();
        } catch (JwtException e) {
            log.error("error :: {} ", e.getMessage());
            throw new Unauthorized();
        }

    }

}
