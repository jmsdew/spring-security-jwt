package com.ohgiraffers.security.auth.handler;

import com.ohgiraffers.security.auth.model.DetailsUser;
import com.ohgiraffers.security.auth.service.DetailsService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

public class CustomAuthenticationProvider implements AuthenticationProvider {

    @Autowired
    private DetailsService detailsService;

    @Autowired
    private BCryptPasswordEncoder passwordEncoder;




    @Override // 조회 해온 정보와 토큰 값을 비교하는 메서드
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        // 1. username password token(사용자가 로그인 요청시 날린 아이디와 비밀번호를 가지고 있는 임시 객체)
        UsernamePasswordAuthenticationToken loginToken = (UsernamePasswordAuthenticationToken) authentication;
        String username = loginToken.getName();
        String password = (String) loginToken.getCredentials();  // 토큰이 가지고 있는 값

        // 2. DB에서 username 에 해당하는 정보 조회
        DetailsUser foundUser = (DetailsUser) detailsService.loadUserByUsername(username);

        // 사용자가 입력한 username,password 와 아이디의 비밀번호를 비교하는 로직을 수행함
        if(!passwordEncoder.matches(password, foundUser.getPassword())){  // 입력값과 db값 비교 (암호화 된 값)
            throw new BadCredentialsException("password가 일치하지 않습니다.");
        }



        return new UsernamePasswordAuthenticationToken(foundUser,password, foundUser.getAuthorities());
        //아이디,비밀번호,권한목록 (임시토큰 발행)
    }

    @Override
    public boolean supports(Class<?> authentication) {

        return authentication.equals(UsernamePasswordAuthenticationToken.class);
    }
}
