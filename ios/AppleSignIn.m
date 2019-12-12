#import "AppleSignIn.h"

#import <React/RCTUtils.h>
@implementation AppleSignIn

-(dispatch_queue_t)methodQueue
{
    return dispatch_get_main_queue();
}

RCT_EXPORT_MODULE()

-(NSDictionary *)constantsToExport API_AVAILABLE(ios(13.0)) {
if (@available(iOS 13.0, *)) {
  NSDictionary* scopes = @{@"FULL_NAME": ASAuthorizationScopeFullName, @"EMAIL": ASAuthorizationScopeEmail};
  NSDictionary* operations = @{
    @"LOGIN": ASAuthorizationOperationLogin,
    @"REFRESH": ASAuthorizationOperationRefresh,
    @"LOGOUT": ASAuthorizationOperationLogout,
    @"IMPLICIT": ASAuthorizationOperationImplicit
  };
  NSDictionary* credentialStates = @{
    @"AUTHORIZED": @(ASAuthorizationAppleIDProviderCredentialAuthorized),
    @"REVOKED": @(ASAuthorizationAppleIDProviderCredentialRevoked),
    @"NOT_FOUND": @(ASAuthorizationAppleIDProviderCredentialNotFound),
  };
  NSDictionary* userDetectionStatuses = @{
    @"LIKELY_REAL": @(ASUserDetectionStatusLikelyReal),
    @"UNKNOWN": @(ASUserDetectionStatusUnknown),
    @"UNSUPPORTED": @(ASUserDetectionStatusUnsupported),
  };

  return @{
           @"Scope": scopes,
           @"Operation": operations,
           @"CredentialState": credentialStates,
           @"UserDetectionStatus": userDetectionStatuses
           };
} else {
    return @{};
}
}


+ (BOOL)requiresMainQueueSetup
{
  return YES;
}


RCT_EXPORT_METHOD(requestAsync:(NSDictionary *)options
                  resolver:(RCTPromiseResolveBlock)resolve
                  rejecter:(RCTPromiseRejectBlock)reject)
{
  _promiseResolve = resolve;
  _promiseReject = reject;

  ASAuthorizationAppleIDProvider* appleIDProvider = [[ASAuthorizationAppleIDProvider alloc] init];
  ASAuthorizationAppleIDRequest* request = [appleIDProvider createRequest];
  request.requestedScopes = options[@"requestedScopes"];
  if (options[@"requestedOperation"]) {
    request.requestedOperation = options[@"requestedOperation"];
  }

  ASAuthorizationController* ctrl = [[ASAuthorizationController alloc] initWithAuthorizationRequests:@[request]];
  ctrl.presentationContextProvider = self;
  ctrl.delegate = self;
  [ctrl performRequests];
}


- (ASPresentationAnchor)presentationAnchorForAuthorizationController:(ASAuthorizationController *)controller API_AVAILABLE(ios(13.0)) {
  return RCTKeyWindow();
}


- (void)authorizationController:(ASAuthorizationController *)controller
   didCompleteWithAuthorization:(ASAuthorization *)authorization API_AVAILABLE(ios(13.0)) {
ASAuthorizationAppleIDCredential* credential = authorization.credential;
  NSDictionary *givenName;
  NSDictionary *familyName;
  if (credential.fullName) {
    givenName = RCTNullIfNil(credential.fullName.givenName);
    familyName = RCTNullIfNil(credential.fullName.familyName);
  }

  NSString *authorizationCode;
  if (credential.authorizationCode) {
    authorizationCode = [[NSString alloc] initWithData:credential.authorizationCode encoding:NSUTF8StringEncoding];
  }
  NSString *identityToken;
  if (credential.identityToken) {
    identityToken = [[NSString alloc] initWithData:credential.identityToken encoding:NSUTF8StringEncoding];
  }

  NSDictionary* user = @{
                         @"authorizationCode": RCTNullIfNil(authorizationCode),
                         @"identityToken": RCTNullIfNil(identityToken),
                         @"firstName": givenName,
                         @"lastName": familyName,
                         @"email": RCTNullIfNil(credential.email),
                         @"user": credential.user,
                         };
  _promiseResolve(user);
}


-(void)authorizationController:(ASAuthorizationController *)controller
           didCompleteWithError:(NSError *)error {
    NSLog(@" Error code%@", error);
  _promiseReject(@"authorization", error.description, error);
}

@end
