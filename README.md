# NOTE

I made this public because I'm live-streaming the creation of it, not because it's ready for consumption:

LIVE CODING Recordings: https://www.youtube.com/playlist?list=PLxki0D-ilnqYmidRxvrQoF2jX67wH5OS0

# auth3000

Yet another auth library by AJ

Exchange Long-Lived (24h - 90d) Refresh Token (in Cookie) for Short-Lived (15m - 24h) Session Token.

## POST /api/authn/session

Request

```txt
POST /api/auth/session

```

```json
{
  "user": "john.doe@gmail.com",
  "pass": "secret",
  "account": 0
}
```

Response

```txt
200 OK
Set-Cookie: xxxxx

```

```json
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

```

```json
{ "account": 0 }
```

Response

```txt
200 OK
Set-Cookie: xxxxx

```

```json
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

```

```json
{ "account": 0 }
```

Response

```txt
200 OK

```

```json
{
  "access_token": "xxxx.yyyy.zzzz"
}
```

# Resources

- [Live Recordings](https://www.youtube.com/playlist?list=PLxki0D-ilnqYmidRxvrQoF2jX67wH5OS0) of the making of this project
- [Express Cookies Cheat Sheet](https://github.com/BeyondCodeBootcamp/beyondcodebootcamp.com/blob/main/articles/express-cookies-cheatsheet.md)
- [How to add Google Sign In](https://therootcompany.com/blog/google-sign-in-javascript-api/)
