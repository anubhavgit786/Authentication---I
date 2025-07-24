package com.anubhav.security.controllers;

import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/v1/manager")
public class ManagerController
{
    @GetMapping
    public String get()
    {
        return "GET : Manager Controller";
    }

    @PostMapping
    public String post()
    {
        return "POST : Manager Controller";
    }

    @PutMapping
    public String put()
    {
        return "PUT : Manager Controller";
    }

    @DeleteMapping
    public String delete()
    {
        return "DELETE : Manager Controller";
    }
}

