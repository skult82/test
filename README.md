# Nginx Security Hardening Configuration
# Based on Information System Security Technical Operation Manual

# Temporary file paths for Docker environment
client_body_temp_path /var/its/temp/nginx/client_body;
proxy_temp_path       /var/its/temp/nginx/proxy;

# nitst.ex.co.kr (Main Service)
server {
    access_log /var/log/nginx/nitst-access.log;
    error_log /var/log/nginx/nitst-error.log warn;

    # Listen on existing ports (Constraint: Port preservation)
    listen 443 ssl;
    listen 11443 ssl;
    server_name nitst.ex.co.kr;

    # SSL Security Hardening (E-9, O-15)
    ssl_certificate /etc/nginx/conf.d/cert/ex/wildcard.crt;
    ssl_certificate_key /etc/nginx/conf.d/cert/ex/wildcard.key;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_prefer_server_ciphers on;
    ssl_ciphers 'ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384';

    # Support for Large File Uploads (4GB)
    client_max_body_size 4096M;

    # Timeouts (E-18, U-54)
    keepalive_timeout 600s;
    client_header_timeout 600s;
    client_body_timeout 600s;
    send_timeout 600s;

    proxy_connect_timeout 600s;
    proxy_send_timeout 600s;
    proxy_read_timeout 600s;

    # Information Hiding (E-10, U-71)
    server_tokens off;

    # Security Headers (Section 6 - Web Application Security)
    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-XSS-Protection "1; mode=block" always;
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
    add_header Referrer-Policy "strict-origin-when-cross-origin" always;
    # 기존
    # add_header Content-Security-Policy "default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self'; connect-src 'self' https://aiserver.kasolutions.kr;" always;

    # 변경 (frame-src, object-src, worker-src, img-src 등에 blob: 추가)
    add_header Content-Security-Policy "
        default-src 'self';
        script-src 'self' 'unsafe-inline' 'unsafe-eval';
        style-src 'self' 'unsafe-inline';
        img-src 'self' data: blob:;
        font-src 'self';
        connect-src 'self' https://aiserver.kasolutions.kr;
        frame-src 'self' blob:;
        object-src 'self' blob:;
        worker-src 'self' blob:;"
        always;

    add_header 'Access-Control-Expose-Headers' 'Content-Disposition' always;

    # HTTP Method Limitation (Allow GET, POST, HEAD, OPTIONS, PUT, DELETE, PATCH)
    if ($request_method !~ ^(GET|POST|HEAD|OPTIONS|PUT|DELETE|PATCH)$ ) {
        return 405;
    }

    # Standard Error Pages (E-7)
    error_page 404 /404.html;
    location = /404.html {
        root /var/its/builds/fe/error;
        internal;
    }
    error_page 500 502 503 504 /50x.html;
    location = /50x.html {
        root /var/its/builds/fe/error;
        internal;
    }

    location /api/ai/ {
        proxy_pass https://aiserver.kasolutions.kr/api/;

        proxy_ssl_server_name on;
        proxy_ssl_name aiserver.kasolutions.kr;
        proxy_ssl_protocols TLSv1.2 TLSv1.3;

        proxy_set_header Host aiserver.kasolutions.kr;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_set_header X-Forwarded-Prefix /api/ai;
        proxy_set_header X-Forwarded-Port 11443;
    }

    location /api/sso/ {
        proxy_pass http://localhost:8080/sso/;

        proxy_set_header Host $http_host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_set_header X-Forwarded-Prefix /api/sso;
        proxy_set_header X-Forwarded-Port 11443;

        proxy_cookie_path /sso/ /api/sso/;
        proxy_cookie_path /sso /api/sso;

        proxy_redirect http://localhost:8080/sso/ /api/sso/;
    }

    location /api/ {
        proxy_pass http://localhost:60211/;

        proxy_set_header Host $http_host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_set_header X-Forwarded-Prefix /api;
        proxy_set_header X-Forwarded-Port 11443;

        add_header Access-Control-Expose-Headers "X-Video-Frame-Rate" always;

        proxy_pass_header Cookie;
    }

    location / {
        include mime.types;
        types {
            application/javascript  mjs;
            application/wasm        wasm;
        }

        root /var/its/builds/fe/manager/current/;
        absolute_redirect off;
        autoindex off; # (E-6, U-35)

        index index.html;
        try_files $uri $uri.html /index.html;
    }
}

# itst.ex.co.kr (Security Inspection Service)
server {
    access_log /var/log/nginx/itst-access.log;
    error_log /var/log/nginx/itst-error.log warn;

    listen 443 ssl;
    listen 11443 ssl;
    server_name itst.ex.co.kr;

    # SSL Security Hardening (E-9)
    ssl_certificate /etc/nginx/conf.d/cert/ex/wildcard.crt;
    ssl_certificate_key /etc/nginx/conf.d/cert/ex/wildcard.key;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_prefer_server_ciphers on;
    ssl_ciphers 'ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384';

    client_max_body_size 4096M;

    # Optimization for form-data and auth_request (Solve 500 error/Broken Pipe)
    client_body_buffer_size 10M;
    client_body_in_single_buffer on;

    # Timeouts (E-18, U-54)
    keepalive_timeout 600s;
    client_header_timeout 600s;
    client_body_timeout 600s;
    send_timeout 600s;

    proxy_connect_timeout 600s;
    proxy_send_timeout 600s;
    proxy_read_timeout 600s;

    server_tokens off;

    # Security Headers
    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-XSS-Protection "1; mode=block" always;
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
    add_header Referrer-Policy "strict-origin-when-cross-origin" always;
    # TouchEN(34581~3), Delfino/Wizvera(16107,16117), postcode.v2.js(t1.daumcdn.net)
    # VWorld(vworld.kr, tile.openstreetmap.org)
    add_header Content-Security-Policy "
        default-src 'self';
        script-src 'self' 'unsafe-inline' 'unsafe-eval' https://127.0.0.1:16107 https://t1.daumcdn.net https://postcode.map.kakao.com https://map.vworld.kr;
        style-src 'self' 'unsafe-inline' https://map.vworld.kr;
        img-src 'self' data: https://t1.daumcdn.net https://postcode.map.kakao.com https://*.vworld.kr https://*.tile.openstreetmap.org;
        font-src 'self' data: https://map.vworld.kr;
        connect-src 'self' https://127.0.0.1:16107 ws://127.0.0.1:16117 wss://127.0.0.1:34581 wss://127.0.0.1:34582 wss://127.0.0.1:34583;
        frame-src 'self' https://postcode.map.kakao.com;
    " always;
    add_header 'Access-Control-Expose-Headers' 'Content-Disposition' always;

    # HTTP Method Limitation (Allow GET, POST, HEAD, OPTIONS, PUT, DELETE, PATCH)
    if ($request_method !~ ^(GET|POST|HEAD|OPTIONS|PUT|DELETE|PATCH)$ ) {
        return 405;
    }

    # Standard Error Pages (E-7)
    error_page 404 /404.html;
    location = /404.html {
        root /var/its/builds/fe/error;
        internal;
    }
    error_page 500 502 503 504 /50x.html;
    location = /50x.html {
        root /var/its/builds/fe/error;
        internal;
    }

    location /api/wizvera/ {
        proxy_pass http://localhost:60102/;
        proxy_set_header Host $http_host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_set_header X-Forwarded-Prefix /api/wizvera;
        proxy_set_header X-Forwarded-Port 11443;
        proxy_pass_header Cookie;
    }

    location /api/ {
        proxy_pass http://localhost:60100/;

        proxy_set_header Host $http_host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;

        # 운영 web1 설정할 때에는 아래 부분을 주석처리 해야 함
        # 그렇지 않으면 응답 uri 가 /api/api/ 형식이 되어버림
        proxy_set_header X-Forwarded-Prefix /api;
        proxy_set_header X-Forwarded-Port 11443;

        proxy_pass_header Cookie;
    }

    location / {
        root /var/its/builds/fe/request/current/;
        absolute_redirect off;
        autoindex off; # (E-6)

        index index.html;
        try_files $uri $uri.html /index.html;
    }
}

# Default Server (Catch-all)
server {
    access_log /var/log/nginx/access.log;
    error_log /var/log/nginx/error.log warn;

    listen 80 default_server;
    server_name _;

    client_max_body_size 4096M;

    # Timeouts (E-18, U-54)
    keepalive_timeout 600s;
    client_header_timeout 600s;
    client_body_timeout 600s;
    send_timeout 600s;

    proxy_connect_timeout 600s;
    proxy_send_timeout 600s;
    proxy_read_timeout 600s;

    # Information Hiding (E-10, U-71)
    server_tokens off;

    # Security Headers
    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-XSS-Protection "1; mode=block" always;

    # HTTP Method Limitation (Allow GET, POST, HEAD, OPTIONS, PUT, DELETE, PATCH)
    if ($request_method !~ ^(GET|POST|HEAD|OPTIONS|PUT|DELETE|PATCH)$ ) {
        return 405;
    }

    # Error Pages
    error_page 404 /404.html;
    location = /404.html {
        root   /var/its/builds/fe/error;
        internal;
    }
    error_page 500 502 503 504 /50x.html;
    location = /50x.html {
        root   /var/its/builds/fe/error;
        internal;
    }

    location /cicd/ {
        proxy_pass http://localhost:60000;
        proxy_set_header Host $http_host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }

    location /gitlab/ {
        proxy_pass http://localhost:60001;
        proxy_set_header Host $http_host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }

    location / {
        deny all;
        return 403;
    }
}
