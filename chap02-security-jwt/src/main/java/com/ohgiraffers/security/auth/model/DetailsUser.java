package com.ohgiraffers.security.auth.model;

import com.ohgiraffers.security.user.entity.User;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Optional;

public class DetailsUser implements UserDetails {

    //db에서 가져온 값을 틀에 맞춰서 보내주는 역할
    private User user;

    public DetailsUser() {
    }

    public DetailsUser(Optional<User> user) {
        this.user = user.get(); // 빈값이면 에러가 나는데 방지하기 위해서 optional 객체로 반환해줌
    }                   // optional 객체 반환시에는 get 써야함

    public User getUser() {
        return user;
    }

    public void setUser(User user) {
        this.user = user;
    }

    @Override   // 권한설정 --- 중요
    public Collection<? extends GrantedAuthority> getAuthorities() {

        Collection<GrantedAuthority> authorities = new ArrayList<>();
        user.getRoleList().forEach(role -> authorities.add(()->role));

        return authorities;
    }

    @Override
    public String getPassword() {

        return user.getUserPass();
    }

    @Override
    public String getUsername() {
        return user.getUserId();
    }


    // 여기서 아래 내용을 관리하면 DB에 다 들어가 있어야함.  필수요소 X



    @Override
    public boolean isAccountNonExpired() {
        /*
        * 계정 만료 여부 메소드 false이면 사용할 수 없음
        * */
        return true;
    }

    
    @Override
    public boolean isAccountNonLocked() {
        /*
        * 계정이 잠겨있는지 확인하는 메서드 false이면 해당 계정을 사용할 수 없음
        * 반복실패 lock 등의 로직은 여기서 짜 줘야함.
        * */
        return true;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        // 탈퇴 여부 표현 메소드 false면 사용 X
        return true;
    }

    @Override
    public boolean isEnabled() {
        //계정 비활성화 여부 false면 사용 X
        return true;
    }
}
