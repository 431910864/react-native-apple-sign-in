#import "AppleSignIn.h"

#import <React/RCTUtils.h>
@implementation AppleSignIn

-(dispatch_queue_t)methodQueue
{
    return dispatch_get_main_queue();
}

RCT_EXPORT_MODULE()

-(NSDictionary *)constantsToExport API_AVAILABLE(ios(13.0)) {
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
    NSString *identityToken = [[NSString alloc]initWithData:credential.identityToken encoding:NSUTF8StringEncoding];
    NSDictionary* user = @{
                         @"fullName": RCTNullIfNil(credential.fullName),
                         @"email": RCTNullIfNil(credential.email),
                         @"user": credential.user,
                         @"authorizedScopes": credential.authorizedScopes,
                         @"realUserStatus": @(credential.realUserStatus),
                         @"state": RCTNullIfNil(credential.state),
                         @"authorizationCode": RCTNullIfNil(credential.authorizationCode),
                         @"identityToken": RCTNullIfNil(identityToken),
                         };
  _promiseResolve(user);
}

// + (id)jwtDecodeWithJwtString:(NSString *)jwtStr {
//
//     NSArray * segments = [jwtStr componentsSeparatedByString:@"."];
//     NSString * base64String = [segments objectAtIndex:1];
//
//     int requiredLength = (int)(4 *ceil((float)[base64String length]/4.0));
//     int nbrPaddings = requiredLength - (int)[base64String length];
//     if(nbrPaddings > 0) {
//         NSString * pading = [[NSString string] stringByPaddingToLength:nbrPaddings withString:@"=" startingAtIndex:0];
//         base64String = [base64String stringByAppendingString:pading];
//     }
//     base64String = [base64String stringByReplacingOccurrencesOfString:@"-" withString:@"+"];
//     base64String = [base64String stringByReplacingOccurrencesOfString:@"_" withString:@"/"];
//     NSData * decodeData = [[NSData alloc] initWithBase64EncodedData:[base64String dataUsingEncoding:NSUTF8StringEncoding] options:0];
//     NSString * decodeString = [[NSString alloc] initWithData:decodeData encoding:NSUTF8StringEncoding];
//     NSDictionary * jsonDict = [NSJSONSerialization JSONObjectWithData:[decodeString dataUsingEncoding:NSUTF8StringEncoding] options:0 error:nil];
//     return jsonDict;
// }


// -(void)authorizationController:(ASAuthorizationController *)controller
//            didCompleteWithError:(NSError *)error API_AVAILABLE(ios(13.0)){
//     NSLog(@" Error code%@", error);
//   _promiseReject(@"authorization", error.description, error);
// }
// RCT_EXPORT_METHOD(sampleMethod:(NSString *)stringArgument numberParameter:(nonnull NSNumber *)numberArgument callback:(RCTResponseSenderBlock)callback)
// {
//     // TODO: Implement some actually useful functionality
//     callback(@[[NSString stringWithFormat: @"numberArgument: %@ stringArgument: %@", numberArgument, stringArgument]]);
// }


@end
