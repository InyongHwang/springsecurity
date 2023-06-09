package com.sparta.springsecurity.security;

import com.sparta.springsecurity.entity.User;
import com.sparta.springsecurity.entity.UserRoleEnum;
import org.springframework.security.core.GrantedAuthority;

import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.ArrayList;
import java.util.Collection;

public class UserDetailsImpl implements UserDetails {


    //-------------------------------------------------------------------//
    // 인증이 완료된 사용자 추가
    //-------------------------------------------------------------------//
    private final User user; // 인증이 완료된 User 객체
    private final String username; // 인증이 완료된 User의 ID
    private final String password; // 인증이 완료된 User의 PWD

    public UserDetailsImpl(User user, String username, String password) {
        this.user = user;
        this.username = username;
        this.password = password;
    }

    // 인증 완료된 User를 가져오는 Getter
    public User getUser() {
        return user;
    }
    //-------------------------------------------------------------------//

    //-------------------------------------------------------------------//
    // 사용자의 권한 GrantedAuthority 로 추상화 및 반환
    //-------------------------------------------------------------------//
    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() { // user의 권한을 가져오는 메서드
        UserRoleEnum role = user.getRole();
        String authority = role.getAuthority(); // user의 권한을 String 값으로 변환

        // 가져온 권한을 추상화함.
        SimpleGrantedAuthority simpleGrantedAuthority = new SimpleGrantedAuthority(authority);
        Collection<GrantedAuthority> authorities = new ArrayList<>();
        authorities.add(simpleGrantedAuthority);

        return authorities;
    }
    //-------------------------------------------------------------------//

    @Override
    public String getPassword() {
        return this.password;
    }

    @Override
    public String getUsername() {
        return this.username;
    }

    @Override
    public boolean isAccountNonExpired() {
        return false;
    }

    @Override
    public boolean isAccountNonLocked() {
        return false;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return false;
    }

    @Override
    public boolean isEnabled() {
        return false;
    }
}
