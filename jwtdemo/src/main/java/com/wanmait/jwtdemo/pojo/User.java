package com.wanmait.jwtdemo.pojo;

import lombok.Data;

@Data
public class User {
    private int id;
    private String username;
    private String password;
    private String name;
}
