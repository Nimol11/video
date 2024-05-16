function FindProxyForURL(url, host) {
    // Use proxy for all URLs except local addresses
    if (shExpMatch(host, "*.local") || isPlainHostName(host)) {
        return "DIRECT";
    }
    // Use proxy for all other URLs
    return "PROXY proxy.example.com:8080";
}
