# hoxy

Simple proxy server that redirects all reuqest to a single server and modifies the host and location headers to make it plausible and allow to choose the virtual host to retrieve. 

This is e.g. useful to test virtual host server configurations without changing the DNS settings, access inaccesible servers through a VPN or SSH session, or inject basic authentication information for clients that don't support this directly.

### examples

- Redirect all requests using an ssl connection to example.com.

  ```hoxy.py https://example.com/```

- Redirect all requests to 192.168.1.123, but set the host header to example.com.

  ```hoxy.py http://192.168.1.123/ example.com```

- Redirect all requests to example.com and send username and password with all reqeusts.

  ```hoxy.py http://user:password@example.com/```

Then point your browser to [http://localhost:8080/](http://localhost:8080/).
