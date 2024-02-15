package com.ohgiraffers.security.auth.filter;

import jakarta.servlet.*;
import jakarta.servlet.http.HttpServletResponse;

import java.io.IOException;

public class HeaderFilter implements Filter {

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {

        HttpServletResponse res = (HttpServletResponse) response;
        res.setHeader("Access-Control-Allow-Origin", "*"); // 외부 요청 응답 허용 여부 등록
        res.setHeader("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE"); // 외부 리소스 요청 허용 여부
        res.setHeader("Access-Control-Max-Age", "3600"); // 외부 캐싱
        res.setHeader("Access-Control-Allow-Headers", "X-Requested-With, Content-Type, Authorization, X-XSRF-token");  // 어떤 헤더 요청을 허용 할지
        res.setHeader("Access-Control-Allow-Credentials", "false"); //서버가 인증 정보를 포함하지 않도록 설정
        chain.doFilter(request,response);
    }
}
