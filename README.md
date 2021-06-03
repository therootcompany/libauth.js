# auth3000

Yet another auth library by AJ

Exchange Long-Lived (24h - 90d) Refresh Token (in Cookie) for Short-Lived (15m - 24h) Session Token.

## POST /api/authn/session

Request

```txt
POST /api/auth/session

{ "user": "john.doe@gmail.com", "pass": "secret", "account": 0 }
```

Response

```txt
200 OK
Set-Cookie: xxxxx

{
    "id_token": "xxxx.yyyy.zzzz",
    "access_token": "xxxx.yyyy.zzzz"
}
```

## POST /api/authn/refresh

Request

```txt
POST /api/authn/refresh
Cookie: xxxxx

{ "account": 0 }
```

Response

```txt
200 OK
Set-Cookie: xxxxx

{
    "id_token": "xxxx.yyyy.zzzz",
    "access_token": "xxxx.yyyy.zzzz"
}
```

## POST /api/authn/exchange

Request

```txt
POST /api/authn/exchange
Authorization: Bearer <token>

{ "account": 0 }
```

Response

```txt
200 OK

{
    "access_token": "xxxx.yyyy.zzzz"
}
```
