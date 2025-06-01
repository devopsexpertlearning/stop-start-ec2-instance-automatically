function handler(event) {
    var request = event.request;
    var headers = request.headers;
    var cookies = headers.cookie;
    var uri = request.uri;
    
    // Authentication check for all pages except callback and static resources
    var needsAuthentication = !(uri.startsWith('/callback') || 
        uri.endsWith('.js') || 
        uri.endsWith('.css') || 
        uri.endsWith('.png') || 
        uri.endsWith('.jpg') || 
        uri.endsWith('.html') || 
        uri.endsWith('.svg'));
    
    // Map root to index.html internally (won't show in URL)
    if (uri === '/' || uri === '') {
        request.uri = '/index.html';
        // But don't return yet - check authentication first
    }
    
    // Check if we need to authenticate and no valid token exists
    if (needsAuthentication) {
        // Look for the authentication cookie
        var hasValidToken = cookies && cookies.value && 
            (cookies.value.includes('CognitoIdentityServiceProvider.idToken') || 
             cookies.value.includes('CognitoIdentityServiceProvider.accessToken'));
             
        if (!hasValidToken) {
            // Not authenticated, redirect to Cognito login
            var host = request.headers.host && request.headers.host.value;
            
            var redirectURL = "https://COGNITO_LOGIN_URL/login?" +
                "client_id=CLIENT_ID" +
                "response_type=token&" +
                "scope=email+openid+profile&" +
                "redirect_uri=https://" + host + "/callback.html";
            
            return {
                statusCode: 302,
                statusDescription: "Found",
                headers: {
                    "location": { value: redirectURL },
                    "cache-control": { value: "no-cache, no-store, must-revalidate" }
                }
            };
        }
    }
    
    // If we reached here, the request is either authenticated or doesn't need authentication
    return request;
}
