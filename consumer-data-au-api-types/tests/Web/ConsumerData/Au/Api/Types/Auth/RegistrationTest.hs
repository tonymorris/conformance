{-# LANGUAGE DataKinds           #-}
{-# LANGUAGE LambdaCase          #-}
{-# LANGUAGE OverloadedStrings   #-}
{-# LANGUAGE RankNTypes          #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# OPTIONS_GHC -Wwarn #-}

module Web.ConsumerData.Au.Api.Types.Auth.RegistrationTest where

import           Control.Lens                             (( # ), (^?))
import           Control.Monad                            ((<=<))
import           Control.Monad.Catch
    (Exception, MonadThrow, throwM)
import           Crypto.JWT
    (Alg (..), Audience (Audience), NumericDate (..), StringOrURI,
    decodeCompact, encodeCompact, string, uri)
import           Data.Aeson                               (eitherDecode, encode)
import           Data.ByteString                          (ByteString)
import qualified Data.ByteString.Lazy                     as LBS
import           Data.Maybe                               (isNothing)
import           Data.Set                                 (Set)
import qualified Data.Set                                 as Set
import           Data.Text                                (Text)
import           Data.Time.Calendar                       (fromGregorian)
import           Data.Time.Clock
import           Hedgehog
    (MonadGen, Property, PropertyT, assert, evalEither, evalExceptT, property,
    (===))
import qualified Hedgehog.Gen                             as Gen
import           Hedgehog.Helpers                         (sampleT)
import           Network.URI                              (parseURI)
import           Prelude                                  hiding (exp)
import           Text.URI
    (Authority (Authority), mkHost, mkScheme, renderStr)
import           Text.URI.Gens
    (genAuthority, genScheme, genUri)
import           Web.ConsumerData.Au.Api.Types.Auth.Error (Error)
-- `forAllT` should probs be public: https://github.com/hedgehogqa/haskell-hedgehog/issues/203
import           Control.Monad.Except
    (ExceptT, MonadIO, liftIO, runExceptT)
import           Hedgehog.Internal.Property                      (forAllT)
import qualified Hedgehog.Range                                  as Range
import           Test.Tasty                                      (TestTree)
import           Test.Tasty.Hedgehog                             (testProperty)
import           Web.ConsumerData.Au.Api.Types.Auth.Common
    (ClientIss (..), FapiPermittedAlg (..), RedirectUri (RedirectUri),
    ResponseType (..), Scope (..), mkScopes, _FapiPermittedAlg)
import           Web.ConsumerData.Au.Api.Types.Auth.Gens
import           Web.ConsumerData.Au.Api.Types.Auth.Registration

test_request ::
  [TestTree]
test_request =
  [
  testProperty "The 'redirect_urls' smart constructor only accepts https  && !localhost hosts." redirectUrlsValid
  , testProperty "The 'redirect_urls' smart constructor rejects any non-https or localhost hosts." redirectUrlsInvalid
  , testProperty "Claims round-trips to/from ClaimsMap." claimsRoundTrips
  , testProperty "Redirect request round-trips to/from JWT." regoJwtRoundTrips
  ]

redirectUrlsValid ::
  Property
redirectUrlsValid =
  property $ do
    uris <-getRedirectUrls <$> forAllT genRedirectUrls
    assert (not.null$uris)

redirectUrlsInvalid ::
  Property
redirectUrlsInvalid =
  property $ do
    mRedirectUrl <- (^? _RedirectUrls) <$> forAllT genInvalidRedirectUris
    assert (isNothing mRedirectUrl)

--todo tripping
claimsRoundTrips ::
  Property
claimsRoundTrips =
  property $ do
    md <- forAllT genMeta
    md' <- evalExceptT (aesonClaimsToMetaData $ metaDataToAesonClaims md :: ExceptT Error (PropertyT IO) ClientMetaData)
    md === md'

regoJwtRoundTrips::
  Property
regoJwtRoundTrips =
  property $ do
    rr <- forAllT genRegReq
    (jwk,_) <- forAllT genJWKP256
    let
      ar2jwt :: RegistrationRequest -> ExceptT Error (PropertyT IO) LBS.ByteString
      ar2jwt = fmap encodeCompact . regoReqToJwt jwk
      jwt2ar = jwtToRegoReq (const True) (const True) (const True) (const True) jwk <=< decodeCompact
    (=== rr) <=< evalExceptT . (jwt2ar <=< ar2jwt) $ rr

-- showround :: IO (Either Error RegistrationRequest)
-- showround = do
--   rr <- sampleT genRegReq
--   (jwk,_) <- sampleT genJWK
--   let ar2jwt = fmap encodeCompact . regoReqToJwt jwk
--       jwt2ar = jwt2rego jwk <=< decodeCompact
--   runExceptT $ (jwt2ar <=< ar2jwt) rr


genRegReq::
  ( MonadGen n
  , MonadThrow n
  , MonadIO n
  )
  => n RegistrationRequest
genRegReq =
  RegistrationRequest <$> genHeaders <*> genRegClaims <*> genMeta <*> (DecodedSs <$> genSs)

genHeaders::
  ( MonadGen n
  , MonadThrow n
  , MonadIO n
  )
  => n JwsHeaders
genHeaders =  JwsHeaders <$> genAlg <*> genKid

genRegClaims::
  ( MonadGen n
  , MonadThrow n
  , MonadIO n
  )
  => n JwsRegisteredClaims
genRegClaims = do
  (i,exp) <- genIatExp
  JwsRegisteredClaims <$> (Just . ClientIss <$> genStringOrUri) <*> (Just <$> genAud) <*> pure (Just i) <*> pure (Just exp) <*> (Just <$> genJti)

genStringOrUri::
  ( MonadGen n
  , MonadThrow n
  )
  => n StringOrURI
genStringOrUri = Gen.choice [(uri #) <$> uri', (string #) <$> genText]
  where uri'= m2e BadUri =<< parseURI.renderStr <$> genUri

m2e :: forall m e a.
     (MonadThrow m, Exception e) =>
     e -> Maybe a -> m a
m2e e = maybe (throwM e) pure

-- Generate an iat and exp, with exp being + 1s to 10m later + 1 day
genIatExp ::
  ( MonadGen n
  , MonadIO n
  )
  => n (NumericDate,NumericDate)
genIatExp = do
  iat <- liftIO getCurrentTime
  exp <- NumericDate . flip addUTCTime iat . fromInteger . (+ 86400)
    <$> Gen.integral (Range.linear 1 600)
  return (NumericDate iat, exp)

genNumDate ::
  ( MonadGen n
  )
  => n NumericDate
genNumDate = NumericDate . utc <$> Gen.integral (Range.linear 1 31)
  where utc a = UTCTime (fromGregorian 2018 11 a) (secondsToDiffTime 1)

--TODO: check if multi `aud` URLs are allowed.
genAud::
  ( MonadGen n
  , MonadThrow n
  )
  => n Audience
genAud = Audience <$> Gen.list (Range.linear 10 10) genStringOrUri

genJti ::
  ( MonadGen n)
  => n JTI
genJti  = JTI <$> genText

genMeta ::
  ( MonadGen n
  , MonadThrow n
  )
  => n ClientMetaData
genMeta =
  ClientMetaData <$>
    genAlg <*>
    genApplicationType <*>
    genAuthMeth <*>
    Gen.maybe genGrantTypes <*>
    genScript <*>
    Gen.maybe genScriptUri <*>
    Gen.maybe genContacts <*>
    Gen.maybe genScriptUri <*>
    Gen.maybe genScriptUri <*>
    Gen.maybe genScriptUri <*>
    genSubjectType<*>
    Gen.maybe genHttpsUrl <*>
    Gen.maybe genJwks <*>
    Gen.maybe genRequestUris <*>
    genRedirectUrls <*>
    Gen.maybe (RequestObjectEncryption <$> genAlg <*> Gen.maybe genEnc)     <*>
    Gen.maybe genAlg <*>
    Gen.maybe (IdTokenEncryption <$> genAlg <*> Gen.maybe genEnc) <*>
    Gen.maybe genResponseTypes <*>
    Gen.maybe (DefaultMaxAge <$> Gen.int (Range.linear 1 10000)) <*>
    Gen.maybe Gen.bool <*>
    Gen.maybe genAcr <*>
    Gen.maybe genHttpsUrl <*>
    Gen.maybe (UserInfoEncryption <$> genAlg <*> Gen.maybe genEnc)     <*>
    genAlg <*>
    Gen.maybe genScopes <*>
    Gen.maybe (SoftwareId <$> genText) <*>
    Gen.maybe (SoftwareVersion <$> genText) <*>
    Gen.maybe genNoteEndpoint

genSs::
  ( MonadGen n
  , MonadThrow n
  , MonadIO n
  )
  => n SoftwareStatement
genSs = SoftwareStatement <$> genRegClaims <*> genMeta

genAlg :: ( MonadGen n, MonadThrow n ) => n FapiPermittedAlg
genAlg = m2e BadAlgType =<< ((^? _FapiPermittedAlg) <$> Gen.element [PS256,ES256])

genKid :: ( MonadGen n ) => n FapiKid
genKid  = FapiKid <$> genText

genGrantTypes :: ( MonadGen n , MonadThrow n ) => n FapiGrantTypes
genGrantTypes = m2e BadGrantType $ (^? _FapiGrantTypes ) . GrantTypes . Set.fromList $ [Implicit,AuthorizationCode,RefreshToken]

genApplicationType :: ( MonadGen n , MonadThrow n ) => n FapiApplicationType
genApplicationType = m2e BadApplicationType =<< (^? _FapiApplicationType) <$> Gen.element [Web]

genAuthMeth :: ( MonadGen n , MonadThrow n) => n FapiTokenEndpointAuthMethod
genAuthMeth = m2e BadAuthMeth =<< (^? _FapiTokenEndpointAuthMethod ) <$> (Gen.element [PrivateKeyJwt] <*> genAlg)

genScript :: ( MonadGen n ) => n Script
genScript = Script DefaultLang <$> genText

genScriptUri :: ( MonadGen n , MonadThrow n ) => n ScriptUri
genScriptUri = ScriptUri DefaultLang <$> genUri

genContacts :: ( MonadGen n ) => n RegistrationContacts
genContacts = RegistrationContacts <$> Gen.set (Range.linear 10 10) (EmailAddress <$> genText)

genSubjectType :: ( MonadGen n ) => n SubjectType
genSubjectType = Gen.element [Pairwise]

genJwks :: ( MonadGen n , MonadThrow n ) => n JwkSet
genJwks = Gen.choice [JwksRef . JwksUri <$> genUri , JwksVal <$> genText]

genRequestUris :: ( MonadGen n , MonadThrow n ) => n RequestUris
genRequestUris = RequestUris <$> (Set.fromList . map RequestUri <$> Gen.list (Range.linear 10 10) genUri)

genEnc :: ( MonadGen n ) => n FapiEnc
genEnc = Gen.element [A128CBC_HS256 , A192CBC_HS384 , A256CBC_HS512 , A128GCM , A192GCM , A256GCM]

genResponseTypes :: ( MonadGen n ) => n FapiResponseTypes
genResponseTypes = pure $ FapiResponseTypes CodeIdToken

genSubs  :: ( MonadGen n) => [a] -> n [a]
genSubs as = Gen.shuffle as >>= Gen.subsequence

genAcr :: ( MonadGen n) => n FapiAcrValues
genAcr = FapiAcrValues <$> genText

genScopes :: ( MonadGen n ) => n FapiScopes
genScopes = FapiScopes . mkScopes . Set.fromList <$> genSubs  [ ProfileScope ]

genText :: ( MonadGen n ) => n Text
genText = Gen.text (Range.linear 10 10) Gen.unicode

genBytes :: ( MonadGen n ) => n ByteString
genBytes = Gen.bytes (Range.linear 10 10)

genRedirectUrls::
  ( MonadGen n
  , MonadThrow n
  )
  => n RedirectUrls
genRedirectUrls = do
  https <- mkScheme "https"
  lhAutho <- (\l -> Authority Nothing l Nothing) <$> mkHost "localhost"
  autho <-Gen.filter (/=lhAutho) genAuthority
  mRedirectUris <- (^? _RedirectUrls) . Set.fromList . map RedirectUri <$> genUrls https autho
  maybe (throwM BadRedirectUri) pure mRedirectUris

genInvalidRedirectUris::
  ( MonadGen n
  , MonadThrow n
  )
  => n (Set RedirectUri)
genInvalidRedirectUris = do
  let
    goodScheme = mkScheme "https"
    badAutho = (\l -> Authority Nothing l Nothing) <$> mkHost "localhost"
    scheme = Gen.choice [goodScheme,genScheme]
    autho = Gen.choice [genAuthority,badAutho]
    --filter for those that are https and !localhost (i.e both valid)
    bothvalidf gs ba = Gen.filter (\(s,a) ->not (s == gs && a /= ba))
  gs <- goodScheme
  ba <- badAutho
  (bscheme,bautho) <- bothvalidf gs ba $ (,) <$> scheme <*> autho
  Set.fromList . (map RedirectUri) <$> genUrls bscheme bautho

genNoteEndpoint :: ( MonadGen n, MonadThrow n) => n NotificationEndpoint
genNoteEndpoint = NotificationEndpoint <$> genHttpsUrl

data BadRedirectUri = BadRedirectUri deriving (Show)
instance Exception BadRedirectUri

data BadUri = BadUri deriving (Show)
instance Exception BadUri

data BadGrantType = BadGrantType deriving (Show)
instance Exception BadGrantType

data BadApplicationType = BadApplicationType  deriving (Show)
instance Exception BadApplicationType

data BadAlgType = BadAlgType   deriving (Show)
instance Exception BadAlgType

data BadAuthMeth = BadAuthMeth  deriving (Show)
instance Exception BadAuthMeth

data BadResponseType = BadResponseType  deriving (Show)
instance Exception BadResponseType
