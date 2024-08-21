package com.securityoauth2sample.service;

import com.securityoauth2sample.config.model.OAuth2UserInfo;
import com.securityoauth2sample.config.model.PrincipalDetail;
import com.securityoauth2sample.domain.Member;
import com.securityoauth2sample.repository.MemberRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Collections;
import java.util.Map;
import java.util.Set;

@Slf4j
@RequiredArgsConstructor
@Service
public class OAuth2UserService extends DefaultOAuth2UserService {

    private final MemberRepository memberRepository;

    @Transactional
    @Override
    public OAuth2User loadUser(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException {

        // 1. 인증된 유저 객체 생성
        Map<String, Object> oAuth2UserAttributes = super.loadUser(userRequest).getAttributes();

        // 호스팅 id ( github, google, kakao ), 사용자 이름
        String registrationId = userRequest.getClientRegistration().getRegistrationId();
        String userNameAttributeName = userRequest.getClientRegistration().getProviderDetails()
                .getUserInfoEndpoint().getUserNameAttributeName();
        log.info("[OAuth2UserService] ::::::::::: registrationId: {}, userNameAttributeName: {}", registrationId, userNameAttributeName);

        // 2. 호스팅에 맞는 OAuth2UserInfo 생성
        OAuth2UserInfo oAuth2UserInfo = OAuth2UserInfo.of(registrationId, oAuth2UserAttributes);

        // 3. 유저 정보 조회 및 저장
        Member member = getOrSave(oAuth2UserInfo);

        // 유저 권한
        Set<SimpleGrantedAuthority> authorities = Collections.singleton(new SimpleGrantedAuthority(member.getMemberRole().getKey()));

        return new PrincipalDetail(member, authorities, oAuth2UserAttributes);
    }

    private Member getOrSave(OAuth2UserInfo oAuth2UserInfo) {
        Member member = memberRepository.findByEmail(oAuth2UserInfo.getEmail())
                .orElseGet(oAuth2UserInfo::toEntity);

        return memberRepository.save(member);
    }
}
