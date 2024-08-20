package com.securityoauth2sample.config;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.securityoauth2sample.config.filter.EmailPasswordAuthFilter;
import com.securityoauth2sample.config.filter.JwtAuthFilter;
import com.securityoauth2sample.config.handler.CommonLoginFailHandler;
import com.securityoauth2sample.config.handler.CommonLoginSuccessHandler;
import com.securityoauth2sample.config.handler.Http401Handler;
import com.securityoauth2sample.config.handler.Http403Handler;
import com.securityoauth2sample.config.model.PrincipalDetail;
import com.securityoauth2sample.domain.Member;
import com.securityoauth2sample.repository.MemberRepository;
import com.securityoauth2sample.util.JwtUtils;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.annotation.web.configurers.HeadersConfigurer.FrameOptionsConfig;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.crypto.scrypt.SCryptPasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

import java.util.Collections;

import static org.springframework.boot.autoconfigure.security.servlet.PathRequest.toH2Console;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig {

    private final JwtAuthFilter jwtAuthFilter;
    private final MemberRepository memberRepository;
    private final JwtUtils jwtUtils;

    @Bean
    public WebSecurityCustomizer webSecurityCustomizer() { // security를 적용하지 않을 리소스
        return web -> web.ignoring()
                .requestMatchers("/favicon.ico")
                .requestMatchers("/error")
                .requestMatchers(toH2Console());
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {

        http
                .cors(AbstractHttpConfigurer::disable)
                .csrf(AbstractHttpConfigurer::disable)
                .httpBasic(AbstractHttpConfigurer::disable) // 기본 인증 로그인 비활성화
                .formLogin(AbstractHttpConfigurer::disable) // 기본 login form 비활성화
                .logout(AbstractHttpConfigurer::disable) // 기본 logout 비활성화
                .headers(c -> c.frameOptions(
                        FrameOptionsConfig::disable).disable()) // X-Frame-Options 비활성화

                // 세션 설정 NEVER: 기존에 세션이 존재하면 사용, STATELESS: 사용 안함
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))

                // 권한이 없으면 해당 uri 제외하고 접근 불가
                .authorizeHttpRequests(authorize -> authorize
                        .requestMatchers(
                                new AntPathRequestMatcher("/"),
                                new AntPathRequestMatcher("/test"),
                                new AntPathRequestMatcher("/auth/signUp"),
                                new AntPathRequestMatcher("/auth/login"),
                                new AntPathRequestMatcher("/auth/success")
                        )
                        .permitAll()
                        .anyRequest()
                        .authenticated()
                )

//                .oauth2Login(oauth -> // OAuth2 로그인 기능에 대한 여러 설정의 진입점
//                        // OAuth2 로그인 성공 이후 사용자 정보를 가져올 때의 설정을 담당
//                        oauth.userInfoEndpoint(c -> c.userService(oAuth2UserService))
//                                .successHandler(oAuth2SuccessHandler))

                .addFilterBefore(jwtAuthFilter, UsernamePasswordAuthenticationFilter.class)
//                .addFilterBefore(emailPasswordAuthFilter(), UsernamePasswordAuthenticationFilter.class)
                .exceptionHandling(e -> e
                        .accessDeniedHandler(new Http403Handler())
                        .authenticationEntryPoint(new Http401Handler())
                );

        return http.build();
    }

    /**
     * 커스텀마이징한 유저 정보 인증 필터
     * @return
     */
    @Bean
    public EmailPasswordAuthFilter emailPasswordAuthFilter() {
        EmailPasswordAuthFilter filter = new EmailPasswordAuthFilter(new ObjectMapper());
        filter.setAuthenticationManager(authenticationManager());
        // 로그인 성공 url
        filter.setAuthenticationSuccessHandler(new CommonLoginSuccessHandler(jwtUtils));
        // 로그인 실패
        filter.setAuthenticationFailureHandler(new CommonLoginFailHandler());
        return filter;
    }

    /**
     * provider 설정
     * @return
     */
    @Bean
    public AuthenticationManager authenticationManager() {
        DaoAuthenticationProvider provider = new DaoAuthenticationProvider();
        provider.setUserDetailsService(userDetailsService());
        provider.setPasswordEncoder(passwordEncoder());
        return new ProviderManager(provider);
    }

    /**
     * UserDetailsService 구현체
     * @return
     */
    @Bean
    public UserDetailsService userDetailsService() {
        return username -> {
            Member member = memberRepository.findByEmail(username)
                    .orElseThrow(() -> new UsernameNotFoundException(username + "를 찾을 수 없습니다."));
            return new PrincipalDetail(member, Collections.singleton(new SimpleGrantedAuthority(member.getMemberRole().getKey())));
        };
    }

    /**
     * User Password 인코딩 (Scrypt)
     * @return
     */
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new SCryptPasswordEncoder(
                16,
                8,
                1,
                32,
                64);
    }

}
