package com.wanmait.jwtdemo.mapper;

import com.wanmait.jwtdemo.pojo.User;
import org.apache.ibatis.annotations.Mapper;
import org.apache.ibatis.annotations.Param;
import org.apache.ibatis.annotations.Select;

@Mapper
public interface UserMapper {
    @Select("select * from user where username=#{username} and password=#{password}")
    User findByUserNameAndPassword(@Param("username") String username,@Param("password") String password);
}
