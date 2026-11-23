package com.example;

import javax.net.ssl.SSLContext;

public class LegacyTls {

    public SSLContext legacyContext() throws Exception {
        return SSLContext.getInstance("TLSv1"); // 약한 TLS 프로토콜 (java:S4423) — 기존 코드
    }

    public String version() {
        return "1.0";
    }
}