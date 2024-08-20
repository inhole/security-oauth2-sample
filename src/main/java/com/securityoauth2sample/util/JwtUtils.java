package com.securityoauth2sample.util;

import com.securityoauth2sample.config.model.PrincipalDetail;
import com.securityoauth2sample.config.properties.JwtProperties;
import com.securityoauth2sample.domain.Member;
import com.securityoauth2sample.domain.Token;
import com.securityoauth2sample.exception.jwt.CustomJwtException;
import com.securityoauth2sample.exception.jwt.InvalidTokenException;
import com.securityoauth2sample.service.TokenService;
import io.jsonwebtoken.*;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;

import javax.crypto.SecretKey;
import java.time.ZonedDateTime;
import java.util.*;

@Slf4j
@RequiredArgsConstructor
@Component
public class JwtUtils {

    private final JwtProperties jwtProperties;
    private final TokenService tokenService;

    public String generateKey() {
        // 암호화 키 생성
        SecretKey key2 = Jwts.SIG.HS256.key().build();
        byte[] encodedKey = key2.getEncoded();
        String strKey = Base64.getEncoder().encodeToString(encodedKey);
        log.info("strKey :: {}", strKey);
        return strKey;
    }

    /**
     * AccessToken 생성
     * @param authentication
     * @return
     */
    public String generateAccessToken(Authentication authentication) {
        return generateToken(authentication, jwtProperties.getAccessExpTime());
    }

    /**
     * RefreshToken 생성
     * @param authentication
     * @return
     */
    public void generateRefreshToken(Authentication authentication, String accessToken) {
        // redis refreshToken 저장 및 업데이트
        String refreshToken = generateToken(authentication, jwtProperties.getRefreshExpTime());
        tokenService.saveOrUpdate(authentication.getName(), accessToken, refreshToken);
    }

    /**
     * Token 생성
     * @param authentication
     * @param validTime
     * @return
     */
    public String generateToken(Authentication authentication, long validTime) {

        return Jwts.builder()
                .subject(authentication.getName())
                .claim(jwtProperties.getKeyRole(), authentication.getAuthorities())
                .signWith(jwtProperties.getKey())
                .issuedAt(Date.from(ZonedDateTime.now().toInstant()))
                .expiration(Date.from(ZonedDateTime.now().plusMinutes(validTime).toInstant()))
//                .setHeader(Map.of("typ","JWT"))
//                .setClaims(valueMap)
                .compact();
    }

    /**
     * 인증 정보 조회
     * @param token
     * @return
     */
    public Authentication getAuthentication(String token) {
        // 1. Claims 추출
        Claims claims = parseClaims(token);

        // 2. 권한 추출
        List<SimpleGrantedAuthority> authorities = Collections.singletonList(new SimpleGrantedAuthority(jwtProperties.getKeyRole()));

        // 3. PrincipalDetail 객체 생성
        Member member = Member.builder()
                .email(claims.getSubject())
                .build();
        PrincipalDetail principal = new PrincipalDetail(member, authorities);
//        User principal = new User(claims.getSubject(), "", authorities);

        return new UsernamePasswordAuthenticationToken(principal, token, authorities);
    }

    /**
     * Token 검증
     * @param token
     * @return
     */
    public boolean validateToken(String token) {
        if (!StringUtils.hasText(token)) {
            return false;
        }

        // 만료일 체크
        Claims claims = parseClaims(token);
        return claims.getExpiration().after(new Date());
    }


    /**
     * 토큰의 남은 만료시간 계산
     */
    public long tokenRemainTime(Integer expTime) {
        Date expDate = new Date((long) expTime * (1000));
        long remainMs = expDate.getTime() - System.currentTimeMillis();
        return remainMs / (1000 * 60);
    }

    /**
     * Claims 추출/검증
     * @param token
     * @return
     */
    private Claims parseClaims(String token) {
        try {
            Jws<Claims> claims = Jwts.parser()
                    .verifyWith(jwtProperties.getKey())
                    .build()
                    .parseSignedClaims(token);
            return claims.getPayload();
        } catch (ExpiredJwtException e) {
            return e.getClaims();
        } catch (MalformedJwtException e) {
            throw new InvalidTokenException();
        } catch (JwtException e) {
            log.error("error :: {} ", e.getMessage());
            throw new CustomJwtException();
        }

    }

    /**
     * AccessToken 만료시 reFreshToken 검증 후 재발급
     * @param accessToken
     * @return
     */
    public String issueAccessToken(String accessToken) {
        // 1. null 체크
        if (!StringUtils.hasText(accessToken)) return null;

        // 2. token 추출
        Token token = tokenService.findByAccessTokenOrThrow(accessToken);
        String refreshToken = token.getRefreshToken();

        // 3. refreshToken 검증
        if (!validateToken(refreshToken)) return null;

        // 4. accessToken 재발행
        String issueAccessToken = generateAccessToken(getAuthentication(refreshToken));
        tokenService.updateToken(issueAccessToken, token);
        return issueAccessToken;
    }
}
