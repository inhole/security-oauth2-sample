package com.securityoauth2sample.util;

import com.securityoauth2sample.config.model.PrincipalDetail;
import com.securityoauth2sample.config.AppConfig;
import com.securityoauth2sample.domain.Member;
import com.securityoauth2sample.domain.MemberRole;
import com.securityoauth2sample.exception.jwt.CustomExpiredJwtException;
import com.securityoauth2sample.exception.jwt.CustomJwtException;
import com.securityoauth2sample.exception.jwt.Unauthorized;
import io.jsonwebtoken.*;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.time.ZonedDateTime;
import java.util.*;

@Slf4j
@RequiredArgsConstructor
@Component
public class JwtUtils {

    private final AppConfig appConfig;

    // 헤더에 "Bearer XXX" 형식으로 담겨온 토큰을 추출한다
    public String getTokenFromHeader(String header) {
        return header.split(" ")[1];
    }

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
     * @param valueMap
     * @param validTime
     * @return
     */
    public String generateAccessToken(Map<String, Object> valueMap, int validTime) {

        SecretKey key = null;
        try {
            key = appConfig.getKey();
        } catch(Exception e){
            throw new RuntimeException(e.getMessage());
        }
        // TODO :: 밑에 주석으로 바꿔야함 / Deprecated 임  ... 해더에 들어가는거 확인 ...
        return Jwts.builder()
                .setHeader(Map.of("typ","JWT"))
                .setClaims(valueMap)
                .setIssuedAt(Date.from(ZonedDateTime.now().toInstant()))
                .setExpiration(Date.from(ZonedDateTime.now().plusMinutes(validTime).toInstant()))
                .signWith(key)
                .compact();

//        return Jwts.builder()
//                .subject(authentication.getName())
//                .signWith(appConfig.getKey())
//                .issuedAt(new Date()) // 생성 일
//                .expiration(new Date(System.currentTimeMillis() + 1000 * 60 * 60)) // 유효 기간 1시간
//                .compact();
    }

    public Authentication getAuthentication(String token) {
        Map<String, Object> claims = validateToken(token);

        String email = (String) claims.get("email");
        String name = (String) claims.get("name");
        String role = (String) claims.get("role");
        MemberRole memberRole = MemberRole.valueOf(role);

        Member member = Member.builder()
                .email(email)
                .name(name)
                .memberRole(memberRole)
                .build();

        Set<SimpleGrantedAuthority> authorities = Collections.singleton(new SimpleGrantedAuthority(member.getMemberRole().getKey()));
        PrincipalDetail principalDetail = new PrincipalDetail(member, authorities);

        return new UsernamePasswordAuthenticationToken(principalDetail, "", authorities);
    }

    /**
     * Token 검증
     * @param token
     * @return
     */
    public Map<String, Object> validateToken(String token) {
        Map<String, Object> claim = null;
        try {
            SecretKey key = appConfig.getKey();
            claim = Jwts.parser()
                    .setSigningKey(key)
                    .build()
                    .parseClaimsJws(token) // 파싱 및 검증, 실패 시 에러
                    .getBody();
        } catch(ExpiredJwtException expiredJwtException){
            throw new CustomExpiredJwtException(expiredJwtException);
        } catch(Exception e){
            throw new CustomJwtException();
        }
        return claim;
    }


    /**
     * 토큰이 만료되었는지 검증
     * @param token
     * @return
     */
    public boolean isExpired(String token) {
        try {
            validateToken(token);
        } catch (Exception e) {
            return (e instanceof CustomExpiredJwtException);
        }
        return false;
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
